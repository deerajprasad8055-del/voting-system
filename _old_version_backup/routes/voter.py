"""
Voter routes: Dashboard, Encrypted Vote Casting, Receipt Generation, and Verification.
"""

from datetime import datetime, timezone
import json
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from models import db, User, Election, Candidate, VoterStatus, Ballot
from forms import VoteForm, VerifyReceiptForm
from auth_utils import login_required, get_current_user
from crypto_utils import encrypt_vote, compute_ballot_hash, verify_chain, verify_result
from audit_utils import log_audit

voter_bp = Blueprint("voter", __name__)


@voter_bp.route("/")
@voter_bp.route("/dashboard")
@login_required
def dashboard():
    """Voter Dashboard listing open, upcoming, and closed/tallied elections."""
    user = get_current_user()
    if user.is_admin:
        return redirect(url_for("admin.dashboard"))

    all_elections = Election.query.order_by(Election.created_at.desc()).all()
    
    # Get voting status for this user across all elections
    user_statuses = {vs.election_id: vs.has_voted for vs in user.voter_statuses}

    elections_data = []
    for el in all_elections:
        has_voted = user_statuses.get(el.id, False)
        can_vote = el.is_active_for_voting() and not has_voted
        elections_data.append({
            "election": el,
            "has_voted": has_voted,
            "can_vote": can_vote,
            "candidate_count": len(el.candidates),
            "ballot_count": len(el.ballots)
        })

    return render_template("voter/dashboard.html", elections=elections_data, user=user)


@voter_bp.route("/vote/<int:election_id>", methods=["GET", "POST"])
@login_required
def cast_vote(election_id):
    """
    Cast an encrypted vote.
    Enforces:
    - User is logged in
    - Election is active ('open' and within start/end window)
    - User has not already voted in this election (One-Person-One-Vote)
    - Hybrid AES-256-GCM + RSA-OAEP encryption of the ballot
    - SHA-256 Hash Chaining
    - Separation of Voter Participation (VoterStatus) and Ballot content
    """
    user = get_current_user()
    if user.is_admin:
        flash("Administrators cannot cast ballots.", "warning")
        return redirect(url_for("admin.dashboard"))

    election = db.get_or_404(Election, election_id)

    # Validate election status
    if election.status != "open":
        flash(f"Voting is not open for this election (Status: {election.status.upper()}).", "warning")
        return redirect(url_for("voter.dashboard"))

    # Validate window
    if not election.is_within_voting_window():
        flash("This election is currently outside its active voting time window.", "warning")
        return redirect(url_for("voter.dashboard"))

    # Check if candidate list is empty
    if not election.candidates:
        flash("This election has no registered candidates yet.", "danger")
        return redirect(url_for("voter.dashboard"))

    # Check if voter has already voted (One Person One Vote)
    status_entry = VoterStatus.query.filter_by(user_id=user.id, election_id=election.id).first()
    if status_entry and status_entry.has_voted:
        flash("You have already cast your ballot for this election. Votes cannot be recast.", "info")
        return redirect(url_for("voter.dashboard"))

    form = VoteForm()
    # Populate candidate choices
    form.candidate_id.choices = [(c.id, f"{c.name} — {c.party}") for c in election.candidates]

    if form.validate_on_submit():
        candidate_id = form.candidate_id.data
        selected_candidate = Candidate.query.filter_by(id=candidate_id, election_id=election.id).first()
        if not selected_candidate:
            flash("Invalid candidate selection.", "danger")
            return render_template("voter/vote.html", election=election, form=form)

        # Atomic transaction: Double-check participation inside transaction
        try:
            status_entry = VoterStatus.query.filter_by(user_id=user.id, election_id=election.id).first()
            if status_entry and status_entry.has_voted:
                flash("You have already voted in this election.", "danger")
                return redirect(url_for("voter.dashboard"))

            # 1. Encrypt vote with Election RSA Public Key
            enc_result = encrypt_vote(
                candidate_id=candidate_id,
                election_id=election.id,
                public_key=election.public_key_pem
            )

            # 2. Get previous ballot hash for this election to build the hash chain
            last_ballot = Ballot.query.filter_by(election_id=election.id).order_by(Ballot.id.desc()).first()
            prev_hash = last_ballot.ballot_hash if last_ballot else "GENESIS"

            # 3. Compute new ballot hash
            ballot_dict = {
                "prev_hash": prev_hash,
                "encrypted_vote": enc_result["encrypted_vote"],
                "wrapped_key": enc_result["wrapped_key"],
                "nonce": enc_result["nonce"]
            }
            ballot_hash = compute_ballot_hash(ballot_dict, prev_hash)

            # 4. Store Anonymous Ballot (NO voter ID attached)
            ballot = Ballot(
                election_id=election.id,
                encrypted_vote=enc_result["encrypted_vote"],
                wrapped_key=enc_result["wrapped_key"],
                nonce=enc_result["nonce"],
                prev_hash=prev_hash,
                ballot_hash=ballot_hash,
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(ballot)

            # 5. Record Voter Participation
            if not status_entry:
                status_entry = VoterStatus(
                    user_id=user.id,
                    election_id=election.id,
                    has_voted=True,
                    voted_at=datetime.now(timezone.utc)
                )
                db.session.add(status_entry)
            else:
                status_entry.has_voted = True
                status_entry.voted_at = datetime.now(timezone.utc)

            db.session.commit()

            # 6. Audit Log (Never log candidate choice or plain vote!)
            log_audit(
                action="VOTE_CAST",
                details=f"Ballot registered in Election #{election.id}. Ballot Hash prefix: {ballot_hash[:16]}...",
                actor_id=user.id,
                actor_email=user.email
            )

            flash("Your vote has been securely encrypted and cast onto the immutable ballot chain!", "success")
            return redirect(url_for("voter.receipt", ballot_hash=ballot_hash))

        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while processing your ballot: {str(e)}", "danger")
            return render_template("voter/vote.html", election=election, form=form)

    return render_template("voter/vote.html", election=election, form=form)


@voter_bp.route("/receipt/<ballot_hash>")
@login_required
def receipt(ballot_hash):
    """Display cryptographic receipt after casting vote."""
    ballot = Ballot.query.filter_by(ballot_hash=ballot_hash).first_or_404()
    election = db.session.get(Election, ballot.election_id)
    return render_template("voter/receipt.html", ballot=ballot, election=election)


@voter_bp.route("/verify", methods=["GET", "POST"])
def verify():
    """
    Public receipt and hash chain verification tool.
    Voters or auditors can check that a specific ballot hash exists in the chain
    and verify the cryptographic chain integrity.
    """
    form = VerifyReceiptForm()
    verification_result = None

    if form.validate_on_submit():
        target_hash = form.ballot_hash.data.strip()
        ballot = Ballot.query.filter_by(ballot_hash=target_hash).first()

        if ballot:
            election = db.session.get(Election, ballot.election_id)
            all_ballots = Ballot.query.filter_by(election_id=election.id).order_by(Ballot.id.asc()).all()
            is_valid, broken_idx, chain_msg = verify_chain(all_ballots)
            
            # Position in chain
            position = [b.id for b in all_ballots].index(ballot.id) + 1

            verification_result = {
                "found": True,
                "ballot": ballot,
                "election": election,
                "position": position,
                "total_ballots": len(all_ballots),
                "chain_valid": is_valid,
                "chain_message": chain_msg
            }
        else:
            verification_result = {
                "found": False,
                "searched_hash": target_hash
            }

    return render_template("voter/verify.html", form=form, result=verification_result)


@voter_bp.route("/results/<int:election_id>")
def results(election_id):
    """Public results view for tallied elections with cryptographic signature verification."""
    election = db.get_or_404(Election, election_id)
    if election.status != "tallied" or not election.result_json:
        flash("Results are not yet available for this election.", "info")
        return redirect(url_for("voter.dashboard"))

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
        "voter/results.html",
        election=election,
        tally=tally_data,
        is_signature_valid=is_sig_valid
    )
