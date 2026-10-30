"""
Admin routes: Election lifecycle, Candidate management, Tallying with RSA private key,
Integrity checks, Audit viewing, and Results Export (JSON/CSV).
"""

import io
import csv
import json
from datetime import datetime, timezone
from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, session, abort, Response, make_response
)
from models import db, Election, Candidate, Ballot, VoterStatus, AuditLog, User
from forms import CreateElectionForm, CandidateForm, TallyElectionForm
from auth_utils import admin_required, get_current_user
from crypto_utils import (
    generate_rsa_keypair, load_private_key, load_public_key,
    decrypt_vote, verify_chain, sign_result, verify_result
)
from audit_utils import log_audit

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    """Admin Dashboard overview."""
    elections = Election.query.order_by(Election.created_at.desc()).all()
    total_voters = User.query.filter_by(role="voter").count()
    total_ballots = Ballot.query.count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(8).all()

    return render_template(
        "admin/dashboard.html",
        elections=elections,
        total_voters=total_voters,
        total_ballots=total_ballots,
        recent_logs=recent_logs
    )


@admin_bp.route("/election/new", methods=["GET", "POST"])
@admin_required
def create_election():
    """Create a new election and configure its RSA keypair."""
    form = CreateElectionForm()

    if form.validate_on_submit():
        pub_key_pem_str = ""
        generated_priv_pem = None

        if form.key_mode.data == "generate":
            passphrase = form.passphrase.data
            pub_bytes, priv_bytes = generate_rsa_keypair(passphrase)
            pub_key_pem_str = pub_bytes.decode("utf-8")
            generated_priv_pem = priv_bytes.decode("utf-8")
        else:
            pub_key_pem_str = form.public_key_pem.data.strip()

        # Validate that the public key is syntactically valid
        try:
            load_public_key(pub_key_pem_str)
        except Exception as e:
            flash(f"Invalid public key format: {str(e)}", "danger")
            return render_template("admin/create_election.html", form=form)

        start_dt = form.start_time.data
        end_dt = form.end_time.data

        election = Election(
            title=form.title.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            start_time=start_dt,
            end_time=end_dt,
            status="draft",
            public_key_pem=pub_key_pem_str
        )
        db.session.add(election)
        db.session.commit()

        log_audit(
            action="ELECTION_CREATED",
            details=f"Created election ID #{election.id}: '{election.title}'",
            actor_id=session.get("user_id")
        )

        flash(f"Election '{election.title}' created successfully!", "success")

        # If keys were generated, show the private key download / copy prompt once
        if generated_priv_pem:
            return render_template(
                "admin/key_download.html",
                election=election,
                private_key_pem=generated_priv_pem
            )

        return redirect(url_for("admin.manage_candidates", election_id=election.id))

    return render_template("admin/create_election.html", form=form)


@admin_bp.route("/election/<int:election_id>/candidates", methods=["GET", "POST"])
@admin_required
def manage_candidates(election_id):
    """Manage candidates for a draft election."""
    election = db.get_or_404(Election, election_id)
    form = CandidateForm()

    if form.validate_on_submit():
        if election.status not in ["draft", "open"]:
            flash("Cannot add candidates to a closed or tallied election.", "warning")
            return redirect(url_for("admin.manage_candidates", election_id=election.id))

        candidate = Candidate(
            election_id=election.id,
            name=form.name.data.strip(),
            party=form.party.data.strip(),
            description=form.description.data.strip() if form.description.data else None
        )
        db.session.add(candidate)
        db.session.commit()

        log_audit(
            action="CANDIDATE_ADDED",
            details=f"Added candidate '{candidate.name}' ({candidate.party}) to election #{election.id}"
        )
        flash(f"Candidate '{candidate.name}' added successfully.", "success")
        return redirect(url_for("admin.manage_candidates", election_id=election.id))

    return render_template("admin/candidates.html", election=election, form=form)


@admin_bp.route("/election/<int:election_id>/candidate/<int:candidate_id>/delete", methods=["POST"])
@admin_required
def delete_candidate(election_id, candidate_id):
    """Delete a candidate from an election (draft status only)."""
    election = db.get_or_404(Election, election_id)
    if election.status != "draft":
        flash("Candidates can only be removed while the election is in Draft status.", "danger")
        return redirect(url_for("admin.manage_candidates", election_id=election.id))

    candidate = Candidate.query.filter_by(id=candidate_id, election_id=election.id).first_or_404()
    candidate_name = candidate.name
    db.session.delete(candidate)
    db.session.commit()

    log_audit(
        action="CANDIDATE_REMOVED",
        details=f"Removed candidate '{candidate_name}' from election #{election.id}"
    )
    flash(f"Candidate '{candidate_name}' removed.", "info")
    return redirect(url_for("admin.manage_candidates", election_id=election.id))


@admin_bp.route("/election/<int:election_id>/status/<new_status>", methods=["POST"])
@admin_required
def change_status(election_id, new_status):
    """Change election status (open, closed)."""
    election = db.get_or_404(Election, election_id)

    if new_status not in ["open", "closed", "draft"]:
        flash("Invalid status request.", "danger")
        return redirect(url_for("admin.dashboard"))

    if new_status == "open":
        if len(election.candidates) < 2:
            flash("An election requires at least 2 candidates before opening.", "warning")
            return redirect(url_for("admin.manage_candidates", election_id=election.id))

    old_status = election.status
    election.status = new_status
    db.session.commit()

    log_audit(
        action="ELECTION_STATUS_CHANGED",
        details=f"Election #{election.id} status changed from '{old_status}' to '{new_status}'"
    )
    flash(f"Election status updated to '{new_status.upper()}'.", "success")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/election/<int:election_id>/verify-integrity", methods=["GET", "POST"])
@admin_required
def verify_integrity(election_id):
    """Run cryptographic hash chain verification on all ballots for an election."""
    election = db.get_or_404(Election, election_id)
    ballots = Ballot.query.filter_by(election_id=election.id).order_by(Ballot.id.asc()).all()

    is_valid, broken_idx, message = verify_chain(ballots)

    log_audit(
        action="INTEGRITY_CHECK",
        details=f"Chain verification for Election #{election.id}: Valid={is_valid}, BrokenIndex={broken_idx}, TotalBallots={len(ballots)}"
    )

    return render_template(
        "admin/verify_integrity.html",
        election=election,
        ballots=ballots,
        is_valid=is_valid,
        broken_idx=broken_idx,
        message=message
    )


@admin_bp.route("/election/<int:election_id>/tally", methods=["GET", "POST"])
@admin_required
def tally(election_id):
    """
    Tally votes for a closed election.
    Requires the admin to supply the private key PEM and passphrase.
    1. Verifies ballot hash chain integrity first.
    2. Decrypts each ballot with AES-256-GCM + RSA-OAEP.
    3. Tally votes per candidate.
    4. Signs results with RSA-PSS.
    5. Stores certified result and sets status to 'tallied'.
    """
    election = db.get_or_404(Election, election_id)

    if election.status == "tallied":
        flash("This election has already been tallied and certified.", "info")
        return redirect(url_for("admin.results", election_id=election.id))

    if election.status != "closed":
        flash("Election must be closed before tallying votes.", "warning")
        return redirect(url_for("admin.dashboard"))

    form = TallyElectionForm()

    if form.validate_on_submit():
        # Read private key PEM either from file or text
        priv_pem = ""
        if form.private_key_file.data:
            priv_pem = form.private_key_file.data.read().decode("utf-8")
        elif form.private_key_text.data:
            priv_pem = form.private_key_text.data.strip()
        else:
            flash("Please provide the election RSA Private Key (file upload or paste).", "danger")
            return render_template("admin/tally.html", election=election, form=form)

        passphrase = form.passphrase.data.strip()

        # Step 1: Load and unlock Private Key
        try:
            private_key = load_private_key(priv_pem, passphrase)
        except Exception as e:
            flash(f"Failed to unlock private key: Incorrect passphrase or corrupted PEM format. ({str(e)})", "danger")
            log_audit(
                action="TALLY_KEY_UNLOCK_FAILED",
                details=f"Failed key unlock attempt on Election #{election.id}"
            )
            return render_template("admin/tally.html", election=election, form=form)

        # Step 2: Fetch and verify hash chain integrity FIRST
        ballots = Ballot.query.filter_by(election_id=election.id).order_by(Ballot.id.asc()).all()
        is_chain_valid, broken_idx, chain_msg = verify_chain(ballots)
        if not is_chain_valid:
            flash(f"TALLY ABORTED: Hash chain integrity failure detected at ballot index {broken_idx}! {chain_msg}", "danger")
            log_audit(
                action="TALLY_ABORTED_INTEGRITY_FAIL",
                details=f"Integrity check failed during tally on Election #{election.id}: {chain_msg}"
            )
            return render_template("admin/tally.html", election=election, form=form)

        # Step 3: Decrypt each ballot
        candidate_map = {c.id: c for c in election.candidates}
        tally_counts = {c.id: 0 for c in election.candidates}
        invalid_ballots_count = 0
        total_ballots = len(ballots)

        for ballot in ballots:
            try:
                decrypted = decrypt_vote(
                    record=ballot,
                    private_key=private_key
                )
                cand_id = decrypted.get("candidate_id")
                el_id = decrypted.get("election_id")

                if el_id != election.id or cand_id not in tally_counts:
                    invalid_ballots_count += 1
                else:
                    tally_counts[cand_id] += 1
            except Exception as e:
                invalid_ballots_count += 1

        # Step 4: Construct Tally Result Object
        candidate_results = []
        for c in election.candidates:
            votes = tally_counts.get(c.id, 0)
            percentage = round((votes / total_ballots * 100), 2) if total_ballots > 0 else 0.0
            candidate_results.append({
                "candidate_id": c.id,
                "name": c.name,
                "party": c.party,
                "votes": votes,
                "percentage": percentage
            })

        # Sort candidate results by votes descending
        candidate_results.sort(key=lambda x: x["votes"], reverse=True)

        result_data = {
            "election_id": election.id,
            "election_title": election.title,
            "tallied_at": datetime.now(timezone.utc).isoformat(),
            "total_ballots": total_ballots,
            "invalid_ballots": invalid_ballots_count,
            "candidates": candidate_results,
            "chain_verified": True
        }

        result_json_str = json.dumps(result_data, sort_keys=True)

        # Step 5: Digitally Sign Result with RSA-PSS
        try:
            signature_b64 = sign_result(result_json_str, private_key)
        except Exception as e:
            flash(f"Failed to generate digital signature for tally: {str(e)}", "danger")
            return render_template("admin/tally.html", election=election, form=form)

        # Step 6: Commit tally to Database
        election.result_json = result_json_str
        election.result_signature = signature_b64
        election.status = "tallied"
        db.session.commit()

        log_audit(
            action="ELECTION_TALLIED",
            details=f"Election #{election.id} tallied. Total ballots: {total_ballots}. Results signed with RSA-PSS."
        )

        flash("Election successfully decrypted, tallied, and cryptographically certified!", "success")
        return redirect(url_for("admin.results", election_id=election.id))

    return render_template("admin/tally.html", election=election, form=form)


@admin_bp.route("/election/<int:election_id>/results")
@admin_required
def results(election_id):
    """Admin view of official results."""
    election = db.get_or_404(Election, election_id)
    if not election.result_json:
        flash("This election has not been tallied yet.", "info")
        return redirect(url_for("admin.dashboard"))

    try:
        tally_data = json.loads(election.result_json)
    except Exception:
        tally_data = {}

    is_sig_valid = False
    if election.result_signature and election.public_key_pem:
        is_sig_valid = verify_result(
            tally_json=election.result_json,
            signature_b64=election.result_signature,
            public_key=election.public_key_pem
        )

    return render_template(
        "admin/results.html",
        election=election,
        tally=tally_data,
        is_signature_valid=is_sig_valid
    )


@admin_bp.route("/election/<int:election_id>/export/json")
@admin_required
def export_json(election_id):
    """Export election results as JSON."""
    election = db.get_or_404(Election, election_id)
    if not election.result_json:
        flash("No tally results available to export.", "warning")
        return redirect(url_for("admin.dashboard"))

    export_payload = {
        "election": {
            "id": election.id,
            "title": election.title,
            "description": election.description,
            "start_time": election.start_time.isoformat(),
            "end_time": election.end_time.isoformat(),
            "public_key_pem": election.public_key_pem
        },
        "tally": json.loads(election.result_json),
        "signature_rsa_pss": election.result_signature
    }

    response = make_response(json.dumps(export_payload, indent=2))
    response.headers["Content-Type"] = "application/json"
    response.headers["Content-Disposition"] = f"attachment; filename=election_{election.id}_certified_results.json"
    return response


@admin_bp.route("/election/<int:election_id>/export/csv")
@admin_required
def export_csv(election_id):
    """Export election results as CSV."""
    election = db.get_or_404(Election, election_id)
    if not election.result_json:
        flash("No tally results available to export.", "warning")
        return redirect(url_for("admin.dashboard"))

    tally_data = json.loads(election.result_json)
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Election ID", election.id])
    writer.writerow(["Election Title", election.title])
    writer.writerow(["Tallied At", tally_data.get("tallied_at")])
    writer.writerow(["Total Ballots Cast", tally_data.get("total_ballots")])
    writer.writerow(["Invalid Ballots", tally_data.get("invalid_ballots")])
    writer.writerow([])
    writer.writerow(["Rank", "Candidate Name", "Party / Affiliation", "Votes Received", "Percentage (%)"])

    for rank, cand in enumerate(tally_data.get("candidates", []), start=1):
        writer.writerow([
            rank,
            cand.get("name"),
            cand.get("party"),
            cand.get("votes"),
            cand.get("percentage")
        ])

    writer.writerow([])
    writer.writerow(["RSA-PSS Result Signature", election.result_signature])

    output.seek(0)
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = f"attachment; filename=election_{election.id}_certified_results.csv"
    return response


@admin_bp.route("/audit")
@admin_required
def audit_logs():
    """View system audit logs."""
    action_filter = request.args.get("action", "").strip()
    query = AuditLog.query

    if action_filter:
        query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))

    logs = query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    return render_template("admin/audit.html", logs=logs, action_filter=action_filter)
