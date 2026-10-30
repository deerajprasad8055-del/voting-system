"""
SecureVote: Secure Online Voting Data System using RSA + AES
Main Flask Application Factory and Route Handlers.
"""

import os
import json
import re
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, g, abort, jsonify
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
import database
import crypto_utils


def create_app(test_config=None):
    """Application factory for SecureVote."""
    app = Flask(__name__)
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    # Initialize CSRF protection
    csrf = CSRFProtect(app)

    # Initialize keys and DB on startup
    with app.app_context():
        crypto_utils.generate_rsa_keypair(
            keys_dir=app.config.get('KEYS_DIR'),
            passphrase=app.config.get('RSA_PASSPHRASE')
        )
        database.init_db(app.config.get('DATABASE'))

    # Teardown database connection
    app.teardown_appcontext(database.close_db)

    # -------------------------------------------------------------
    # SECURITY HEADERS MIDDLEWARE
    # -------------------------------------------------------------
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:;"
        )
        return response

    # -------------------------------------------------------------
    # CONTEXT PROCESSORS & INJECTORS
    # -------------------------------------------------------------
    @app.context_processor
    def inject_auth_user():
        """Makes current user info accessible in all Jinja templates."""
        user_id = session.get('user_id')
        if not user_id:
            return {'current_user': None}
        db = database.get_db()
        user = db.execute("SELECT id, full_name, email, voter_id, role FROM users WHERE id = ?", (user_id,)).fetchone()
        return {'current_user': user}

    # -------------------------------------------------------------
    # AUTHENTICATION DECORATORS
    # -------------------------------------------------------------
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('user_id'):
                flash("Please log in to access this page.", "warning")
                return redirect(url_for('login', next=request.path))
            return f(*args, **kwargs)
        return decorated_function

    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('user_id'):
                flash("Authentication required.", "warning")
                return redirect(url_for('login', next=request.path))
            if session.get('role') != 'admin':
                flash("Access denied: Administrator privileges required.", "danger")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function

    def voter_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') == 'admin':
                flash("Election administrators are strictly prohibited from casting ballots.", "danger")
                return redirect(url_for('admin_dashboard'))
            return f(*args, **kwargs)
        return decorated_function

    # -------------------------------------------------------------
    # PUBLIC ROUTES
    # -------------------------------------------------------------
    @app.route('/')
    def index():
        """Landing page: Hero, How It Works, Security Features, Live Stats."""
        db = database.get_db()
        elections_count = db.execute("SELECT COUNT(*) FROM elections WHERE status IN ('open', 'closed')").fetchone()[0]
        votes_count = db.execute("SELECT COUNT(*) FROM ballots").fetchone()[0]
        voters_count = db.execute("SELECT COUNT(*) FROM users WHERE role = 'voter'").fetchone()[0]

        return render_template(
            'home.html',
            elections_count=elections_count,
            votes_count=votes_count,
            voters_count=voters_count
        )

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """Voter registration with client/server validation and Werkzeug password hashing."""
        if session.get('user_id'):
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip().lower()
            voter_id = request.form.get('voter_id', '').strip().upper()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            # Basic validation
            errors = []
            if not full_name or len(full_name) < 2:
                errors.append("Full name must be at least 2 characters long.")
            if not email or '@' not in email or '.' not in email:
                errors.append("A valid email address is required.")
            if not voter_id or len(voter_id) < 4:
                errors.append("Voter ID must be at least 4 alphanumeric characters.")
            if len(password) < 8:
                errors.append("Password must be at least 8 characters long.")
            if not re.search(r'[A-Z]', password):
                errors.append("Password must include at least one uppercase letter.")
            if not re.search(r'[a-z]', password):
                errors.append("Password must include at least one lowercase letter.")
            if not re.search(r'[0-9]', password):
                errors.append("Password must include at least one number.")
            if password != confirm_password:
                errors.append("Passwords do not match.")

            if errors:
                for err in errors:
                    flash(err, "danger")
                return render_template('register.html', full_name=full_name, email=email, voter_id=voter_id)

            db = database.get_db()
            # Check uniqueness
            existing = db.execute(
                "SELECT email, voter_id FROM users WHERE email = ? OR voter_id = ?",
                (email, voter_id)
            ).fetchone()

            if existing:
                if existing['email'] == email:
                    flash("An account with this email address already exists.", "danger")
                else:
                    flash("An account with this Voter ID already exists.", "danger")
                return render_template('register.html', full_name=full_name, email=email, voter_id=voter_id)

            # Hash password securely
            pw_hash = generate_password_hash(password, method='scrypt')

            try:
                cursor = db.cursor()
                cursor.execute(
                    """INSERT INTO users (full_name, email, voter_id, password_hash, role)
                       VALUES (?, ?, ?, ?, 'voter')""",
                    (full_name, email, voter_id, pw_hash)
                )
                user_id = cursor.lastrowid
                database.log_audit(
                    db,
                    'USER_REGISTER',
                    f"New voter registered: {voter_id} ({email})",
                    user_id=user_id,
                    ip=request.remote_addr
                )
                db.commit()
                flash("Registration successful! You may now log in to cast your ballot.", "success")
                return redirect(url_for('login'))
            except Exception as e:
                db.rollback()
                flash(f"Registration error: {e}", "danger")

        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """User login with rate-limiting and 5-attempt / 5-minute account lockout protection."""
        if session.get('user_id'):
            return redirect(url_for('admin_dashboard' if session.get('role') == 'admin' else 'dashboard'))

        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            next_url = request.args.get('next')

            if not email or not password:
                flash("Please enter both email and password.", "danger")
                return render_template('login.html', email=email)

            db = database.get_db()
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            now = datetime.now(timezone.utc)

            if user:
                # Check lockout status
                if user['locked_until']:
                    locked_until = user['locked_until']
                    if isinstance(locked_until, str):
                        try:
                            locked_until = datetime.fromisoformat(locked_until)
                        except ValueError:
                            locked_until = None

                    if locked_until and locked_until.tzinfo is None:
                        locked_until = locked_until.replace(tzinfo=timezone.utc)

                    if locked_until and now < locked_until:
                        remaining_seconds = int((locked_until - now).total_seconds())
                        mins = max(1, remaining_seconds // 60)
                        database.log_audit(
                            db,
                            'LOGIN_BLOCKED_LOCKOUT',
                            f"Attempted login while account is locked: {email}",
                            user_id=user['id'],
                            ip=request.remote_addr
                        )
                        flash(f"Account is temporarily locked due to repeated failed logins. Try again in {mins} minute(s).", "danger")
                        return render_template('login.html', email=email)

                # Verify credentials
                if check_password_hash(user['password_hash'], password):
                    # Reset failed attempts
                    db.execute(
                        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                        (user['id'],)
                    )
                    database.log_audit(
                        db,
                        'LOGIN_SUCCESS',
                        f"User logged in: {email} (role: {user['role']})",
                        user_id=user['id'],
                        ip=request.remote_addr
                    )
                    db.commit()

                    session.clear()
                    session.permanent = True
                    session['user_id'] = user['id']
                    session['role'] = user['role']
                    session['full_name'] = user['full_name']
                    session['voter_id'] = user['voter_id']

                    flash(f"Welcome back, {user['full_name']}!", "success")

                    if next_url and next_url.startswith('/'):
                        return redirect(next_url)
                    return redirect(url_for('admin_dashboard' if user['role'] == 'admin' else 'dashboard'))

                else:
                    # Increment failed attempts
                    new_failed = user['failed_attempts'] + 1
                    lockout_time = None
                    if new_failed >= app.config['MAX_FAILED_LOGINS']:
                        lockout_time = now + timedelta(minutes=app.config['LOCKOUT_DURATION_MINUTES'])
                        database.log_audit(
                            db,
                            'ACCOUNT_LOCKED',
                            f"Account locked for 5 minutes after {new_failed} failed attempts: {email}",
                            user_id=user['id'],
                            ip=request.remote_addr
                        )
                        flash("Account locked for 5 minutes due to 5 consecutive failed login attempts.", "danger")
                    else:
                        database.log_audit(
                            db,
                            'LOGIN_FAILED',
                            f"Failed password attempt ({new_failed}/{app.config['MAX_FAILED_LOGINS']}): {email}",
                            user_id=user['id'],
                            ip=request.remote_addr
                        )
                        flash(f"Invalid email or password. Attempt {new_failed} of {app.config['MAX_FAILED_LOGINS']}.", "danger")

                    db.execute(
                        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                        (new_failed, lockout_time.isoformat() if lockout_time else None, user['id'])
                    )
                    db.commit()
            else:
                database.log_audit(
                    db,
                    'LOGIN_FAILED_UNKNOWN',
                    f"Failed login attempt for non-existent user: {email}",
                    ip=request.remote_addr
                )
                flash("Invalid email or password.", "danger")

        return render_template('login.html')

    @app.route('/logout', methods=['GET', 'POST'])
    def logout():
        """Logs out user and clears session."""
        user_id = session.get('user_id')
        if user_id:
            db = database.get_db()
            database.log_audit(db, 'LOGOUT', "User logged out", user_id=user_id, ip=request.remote_addr)
        session.clear()
        flash("You have been securely logged out.", "info")
        return redirect(url_for('index'))

    # -------------------------------------------------------------
    # VOTER ROUTES
    # -------------------------------------------------------------
    @app.route('/dashboard')
    @login_required
    def dashboard():
        """Voter dashboard: Displays Open, Upcoming, and Closed elections with voted status badges."""
        user_id = session['user_id']
        db = database.get_db()

        # Query all elections
        elections = db.execute(
            """SELECT e.*, 
                      (SELECT COUNT(*) FROM candidates WHERE election_id = e.id) as candidate_count,
                      (SELECT COUNT(*) FROM vote_records WHERE election_id = e.id) as total_votes_cast,
                      (SELECT 1 FROM vote_records WHERE election_id = e.id AND user_id = ?) as has_voted
               FROM elections e
               ORDER BY 
                 CASE e.status 
                   WHEN 'open' THEN 1 
                   WHEN 'draft' THEN 2 
                   WHEN 'closed' THEN 3 
                 END, e.created_at DESC""",
            (user_id,)
        ).fetchall()

        # Check if user has tally available for closed elections
        closed_tallies = {}
        tally_records = db.execute("SELECT election_id FROM tally_results").fetchall()
        for t in tally_records:
            closed_tallies[t['election_id']] = True

        return render_template(
            'dashboard.html',
            elections=elections,
            closed_tallies=closed_tallies
        )

    @app.route('/vote/<int:election_id>', methods=['GET', 'POST'])
    @login_required
    @voter_required
    def vote(election_id):
        """
        Voting Interface:
        Enforces NO RE-VOTING at UI, Server, and Database levels.
        Encrypts ballot via Hybrid RSA-2048 + AES-256-GCM.
        """
        user_id = session['user_id']
        db = database.get_db()

        # Retrieve election
        election = db.execute("SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
        if not election:
            flash("Election not found.", "danger")
            return redirect(url_for('dashboard'))

        # Check if already voted (Level 3 - UI/Routing check)
        voted_record = db.execute(
            "SELECT voted_at FROM vote_records WHERE user_id = ? AND election_id = ?",
            (user_id, election_id)
        ).fetchone()

        if voted_record:
            flash("You have already voted in this election. Re-voting is strictly forbidden.", "warning")
            return redirect(url_for('dashboard'))

        if election['status'] != 'open':
            flash(f"This election is {election['status'].upper()} and is not accepting votes.", "warning")
            return redirect(url_for('dashboard'))

        # Fetch candidates
        candidates = db.execute(
            "SELECT * FROM candidates WHERE election_id = ? ORDER BY id ASC",
            (election_id,)
        ).fetchall()

        if not candidates:
            flash("No candidates registered for this election yet.", "warning")
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            candidate_id = request.form.get('candidate_id')
            if not candidate_id:
                flash("Please select a candidate before submitting your ballot.", "danger")
                return render_template('vote.html', election=election, candidates=candidates)

            try:
                candidate_id = int(candidate_id)
            except ValueError:
                flash("Invalid candidate selection.", "danger")
                return render_template('vote.html', election=election, candidates=candidates)

            try:
                # Execute atomic cast vote (Level 1 DB constraint + Level 2 Server transaction)
                receipt_data = database.cast_vote_atomic(
                    db_conn=db,
                    election_id=election_id,
                    user_id=user_id,
                    candidate_id=candidate_id,
                    ip=request.remote_addr
                )

                # Store receipt details in session for the confirmation screen
                session['last_receipt'] = receipt_data
                flash("Your vote has been cryptographically sealed and recorded!", "success")
                return redirect(url_for('receipt', election_id=election_id))

            except ValueError as e:
                flash(str(e), "danger")
                return redirect(url_for('dashboard'))
            except Exception as e:
                flash(f"System error casting ballot: {e}", "danger")
                return redirect(url_for('dashboard'))

        return render_template('vote.html', election=election, candidates=candidates)

    @app.route('/receipt/<int:election_id>')
    @login_required
    def receipt(election_id):
        """
        Vote Receipt & Cryptographic Verification Details:
        Displays the 16-character anonymous receipt code, hash chain link,
        and the Encryption Details panel with shortened ciphertext and RSA-wrapped key.
        """
        user_id = session['user_id']
        db = database.get_db()

        # Check that user actually voted in this election
        has_voted = db.execute(
            "SELECT voted_at FROM vote_records WHERE user_id = ? AND election_id = ?",
            (user_id, election_id)
        ).fetchone()

        if not has_voted:
            flash("You have not voted in this election.", "warning")
            return redirect(url_for('dashboard'))

        election = db.execute("SELECT id, title FROM elections WHERE id = ?", (election_id,)).fetchone()

        # Check if we have the freshly cast receipt in session
        receipt_data = session.get('last_receipt')
        if not receipt_data or receipt_data.get('ballot_id') is None:
            # If user refreshed or navigated back, look up the ballot via the most recent ballot
            # Note: We do NOT link user_id to ballot in DB, so we inform voter to use their saved code
            receipt_data = None

        return render_template(
            'receipt.html',
            election=election,
            receipt_data=receipt_data,
            has_voted=has_voted
        )

    @app.route('/verify', methods=['GET', 'POST'])
    def verify():
        """
        Public / Voter Ballot Verification:
        Allows entering the 16-character receipt code.
        Re-hashes the code with SHA-256 and proves the ballot exists in the chain
        WITHOUT decrypting or revealing what was voted for.
        """
        verification_result = None
        code_input = ""

        if request.method == 'POST':
            code_input = request.form.get('receipt_code', '').strip().upper()
            if not code_input:
                flash("Please enter your 16-character receipt code.", "danger")
            else:
                receipt_hash = crypto_utils.hashlib.sha256(code_input.encode('utf-8')).hexdigest()
                db = database.get_db()
                ballot = db.execute(
                    """SELECT b.id, b.election_id, b.ballot_hash, b.prev_hash, b.created_at, e.title as election_title
                       FROM ballots b
                       JOIN elections e ON b.election_id = e.id
                       WHERE b.receipt_hash = ?""",
                    (receipt_hash,)
                ).fetchone()

                if ballot:
                    verification_result = {
                        'found': True,
                        'ballot_id': ballot['id'],
                        'election_title': ballot['election_title'],
                        'ballot_hash': ballot['ballot_hash'],
                        'prev_hash': ballot['prev_hash'],
                        'created_at': ballot['created_at'],
                        'code': code_input
                    }
                    flash("Ballot found! Your vote is cryptographically secured in the chain.", "success")
                else:
                    verification_result = {
                        'found': False,
                        'code': code_input
                    }
                    flash("No ballot matches this receipt code. Please verify the code and try again.", "danger")

        return render_template('verify.html', result=verification_result, code_input=code_input)

    @app.route('/results/<int:election_id>')
    def results(election_id):
        """
        Election Results:
        STRICT SECURITY RULE: Visible ONLY after the election is CLOSED and TALLIED.
        """
        db = database.get_db()
        election = db.execute("SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
        if not election:
            flash("Election not found.", "danger")
            return redirect(url_for('dashboard' if session.get('user_id') else 'index'))

        if election['status'] != 'closed':
            flash("Results are strictly protected and only accessible after the election has officially CLOSED and been tallied.", "warning")
            return redirect(url_for('dashboard' if session.get('user_id') else 'index'))

        # Fetch tally record
        tally = db.execute("SELECT * FROM tally_results WHERE election_id = ?", (election_id,)).fetchone()
        if not tally:
            flash("This election is closed, but final cryptographic tallying by the election administrator is pending.", "info")
            return render_template('results.html', election=election, tallied=False)

        results_data = json.loads(tally['results_json'])
        return render_template(
            'results.html',
            election=election,
            tallied=True,
            tally=tally,
            results=results_data
        )

    # -------------------------------------------------------------
    # ADMIN ROUTES
    # -------------------------------------------------------------
    @app.route('/admin')
    @admin_required
    def admin_dashboard():
        """Admin overview dashboard: metrics, system health, key status, and quick links."""
        db = database.get_db()
        total_voters = db.execute("SELECT COUNT(*) FROM users WHERE role = 'voter'").fetchone()[0]
        total_elections = db.execute("SELECT COUNT(*) FROM elections").fetchone()[0]
        total_ballots = db.execute("SELECT COUNT(*) FROM ballots").fetchone()[0]
        recent_audits = db.execute(
            """SELECT a.*, u.email as user_email 
               FROM audit_log a 
               LEFT JOIN users u ON a.user_id = u.id 
               ORDER BY a.created_at DESC LIMIT 6"""
        ).fetchall()

        elections = db.execute(
            """SELECT e.*, 
                      (SELECT COUNT(*) FROM candidates WHERE election_id = e.id) as candidate_count,
                      (SELECT COUNT(*) FROM ballots WHERE election_id = e.id) as ballot_count,
                      (SELECT 1 FROM tally_results WHERE election_id = e.id) as is_tallied
               FROM elections e 
               ORDER BY e.created_at DESC"""
        ).fetchall()

        # Check RSA key existence
        keys_status = {
            'pub_exists': os.path.exists(app.config['PUBLIC_KEY_PATH']),
            'priv_exists': os.path.exists(app.config['PRIVATE_KEY_PATH']),
            'key_type': 'RSA-2048 (OAEP SHA-256) + AES-256-GCM'
        }

        return render_template(
            'admin/dashboard.html',
            total_voters=total_voters,
            total_elections=total_elections,
            total_ballots=total_ballots,
            recent_audits=recent_audits,
            elections=elections,
            keys_status=keys_status
        )

    @app.route('/admin/elections/new', methods=['GET', 'POST'])
    @admin_required
    def admin_new_election():
        """Creates a new election in 'draft' status."""
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            start_time = request.form.get('start_time', '').strip()
            end_time = request.form.get('end_time', '').strip()

            if not title:
                flash("Election title is required.", "danger")
                return render_template('admin/election_form.html', action='new')

            db = database.get_db()
            cursor = db.cursor()
            cursor.execute(
                """INSERT INTO elections (title, description, status, start_time, end_time)
                   VALUES (?, ?, 'draft', ?, ?)""",
                (title, description, start_time or None, end_time or None)
            )
            election_id = cursor.lastrowid
            database.log_audit(
                db,
                'ELECTION_CREATED',
                f"Created election #{election_id}: '{title}' (draft)",
                user_id=session['user_id'],
                ip=request.remote_addr
            )
            db.commit()
            flash(f"Election '{title}' created in DRAFT mode. Add candidates before opening voting.", "success")
            return redirect(url_for('admin_manage_candidates', election_id=election_id))

        return render_template('admin/election_form.html', action='new', election=None)

    @app.route('/admin/elections/<int:election_id>/edit', methods=['GET', 'POST'])
    @admin_required
    def admin_edit_election(election_id):
        """Edits an existing election (permitted ONLY while status is draft)."""
        db = database.get_db()
        election = db.execute("SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
        if not election:
            flash("Election not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        if election['status'] != 'draft':
            flash("Elections can only be modified while in DRAFT status.", "warning")
            return redirect(url_for('admin_dashboard'))

        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            start_time = request.form.get('start_time', '').strip()
            end_time = request.form.get('end_time', '').strip()

            if not title:
                flash("Election title is required.", "danger")
                return render_template('admin/election_form.html', action='edit', election=election)

            db.execute(
                """UPDATE elections 
                   SET title = ?, description = ?, start_time = ?, end_time = ? 
                   WHERE id = ?""",
                (title, description, start_time or None, end_time or None, election_id)
            )
            database.log_audit(
                db,
                'ELECTION_UPDATED',
                f"Updated election #{election_id}: '{title}'",
                user_id=session['user_id'],
                ip=request.remote_addr
            )
            db.commit()
            flash("Election details updated successfully.", "success")
            return redirect(url_for('admin_dashboard'))

        return render_template('admin/election_form.html', action='edit', election=election)

    @app.route('/admin/elections/<int:election_id>/delete', methods=['POST'])
    @admin_required
    def admin_delete_election(election_id):
        """Deletes an election (permitted ONLY while status is draft)."""
        db = database.get_db()
        election = db.execute("SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
        if not election:
            flash("Election not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        if election['status'] != 'draft':
            flash("Only elections in DRAFT status can be deleted.", "danger")
            return redirect(url_for('admin_dashboard'))

        db.execute("DELETE FROM candidates WHERE election_id = ?", (election_id,))
        db.execute("DELETE FROM elections WHERE id = ?", (election_id,))
        database.log_audit(
            db,
            'ELECTION_DELETED',
            f"Deleted draft election #{election_id} ('{election['title']}')",
            user_id=session['user_id'],
            ip=request.remote_addr
        )
        db.commit()
        flash("Draft election deleted.", "info")
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/elections/<int:election_id>/status', methods=['POST'])
    @admin_required
    def admin_change_election_status(election_id):
        """Transitions election status: draft -> open, open -> closed."""
        target_status = request.form.get('status')
        if target_status not in ['open', 'closed']:
            flash("Invalid status transition.", "danger")
            return redirect(url_for('admin_dashboard'))

        db = database.get_db()
        election = db.execute("SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
        if not election:
            flash("Election not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        current_status = election['status']

        if target_status == 'open':
            if current_status != 'draft':
                flash("Only draft elections can be opened.", "danger")
                return redirect(url_for('admin_dashboard'))

            # Verify at least 2 candidates exist
            cand_count = db.execute("SELECT COUNT(*) FROM candidates WHERE election_id = ?", (election_id,)).fetchone()[0]
            if cand_count < 2:
                flash("Cannot open election: An election must have at least 2 candidates registered.", "danger")
                return redirect(url_for('admin_manage_candidates', election_id=election_id))

            db.execute("UPDATE elections SET status = 'open' WHERE id = ?", (election_id,))
            database.log_audit(
                db,
                'ELECTION_OPENED',
                f"Election #{election_id} ('{election['title']}') is now OPEN for voting.",
                user_id=session['user_id'],
                ip=request.remote_addr
            )
            db.commit()
            flash(f"Election '{election['title']}' is now officially OPEN for voting!", "success")

        elif target_status == 'closed':
            if current_status != 'open':
                flash("Only open elections can be closed.", "danger")
                return redirect(url_for('admin_dashboard'))

            db.execute("UPDATE elections SET status = 'closed' WHERE id = ?", (election_id,))
            database.log_audit(
                db,
                'ELECTION_CLOSED',
                f"Election #{election_id} ('{election['title']}') voting has been CLOSED.",
                user_id=session['user_id'],
                ip=request.remote_addr
            )
            db.commit()
            flash(f"Election '{election['title']}' has been CLOSED. You can now run the cryptographic tally.", "warning")

        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/elections/<int:election_id>/candidates', methods=['GET', 'POST'])
    @admin_required
    def admin_manage_candidates(election_id):
        """Manage candidates for an election (add, view, remove). Allowed only in draft."""
        db = database.get_db()
        election = db.execute("SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
        if not election:
            flash("Election not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        if request.method == 'POST':
            if election['status'] != 'draft':
                flash("Candidates can only be added while election is in DRAFT mode.", "danger")
                return redirect(url_for('admin_manage_candidates', election_id=election_id))

            name = request.form.get('name', '').strip()
            party = request.form.get('party', '').strip()
            description = request.form.get('description', '').strip()

            if not name:
                flash("Candidate name is required.", "danger")
            else:
                db.execute(
                    "INSERT INTO candidates (election_id, name, party, description) VALUES (?, ?, ?, ?)",
                    (election_id, name, party, description)
                )
                database.log_audit(
                    db,
                    'CANDIDATE_ADDED',
                    f"Candidate '{name}' ({party}) added to election #{election_id}",
                    user_id=session['user_id'],
                    ip=request.remote_addr
                )
                db.commit()
                flash(f"Candidate '{name}' added successfully.", "success")
                return redirect(url_for('admin_manage_candidates', election_id=election_id))

        candidates = db.execute(
            "SELECT * FROM candidates WHERE election_id = ? ORDER BY id ASC",
            (election_id,)
        ).fetchall()

        return render_template(
            'admin/candidate_form.html',
            election=election,
            candidates=candidates
        )

    @app.route('/admin/candidates/<int:candidate_id>/delete', methods=['POST'])
    @admin_required
    def admin_delete_candidate(candidate_id):
        """Deletes a candidate (allowed only in draft)."""
        db = database.get_db()
        cand = db.execute(
            """SELECT c.*, e.status as election_status, e.id as el_id 
               FROM candidates c 
               JOIN elections e ON c.election_id = e.id 
               WHERE c.id = ?""",
            (candidate_id,)
        ).fetchone()

        if not cand:
            flash("Candidate not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        if cand['election_status'] != 'draft':
            flash("Candidates can only be removed while the election is in DRAFT status.", "danger")
            return redirect(url_for('admin_manage_candidates', election_id=cand['el_id']))

        db.execute("DELETE FROM candidates WHERE id = ?", (candidate_id,))
        database.log_audit(
            db,
            'CANDIDATE_DELETED',
            f"Removed candidate #{candidate_id} ('{cand['name']}') from election #{cand['el_id']}",
            user_id=session['user_id'],
            ip=request.remote_addr
        )
        db.commit()
        flash("Candidate removed.", "info")
        return redirect(url_for('admin_manage_candidates', election_id=cand['el_id']))

    @app.route('/admin/verify/<int:election_id>')
    @admin_required
    def admin_verify_election(election_id):
        """Runs the cryptographic hash chain integrity check and shows ballot-by-ballot breakdown."""
        db = database.get_db()
        election = db.execute("SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
        if not election:
            flash("Election not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        is_valid, broken_id, message, ballots_checked = crypto_utils.verify_chain(election_id, db)

        return render_template(
            'admin/verify.html',
            election=election,
            is_valid=is_valid,
            broken_id=broken_id,
            message=message,
            ballots_checked=ballots_checked
        )

    @app.route('/admin/tally/<int:election_id>', methods=['GET', 'POST'])
    @admin_required
    def admin_tally_election(election_id):
        """
        Cryptographic Vote Decryption and Tallying:
        1. Verifies the SHA-256 hash chain. If broken, aborts immediately!
        2. Unwraps each AES-256 key with the RSA private key.
        3. Decrypts ballot JSON with AES-GCM; if authentication tag fails, aborts with TamperError!
        4. Aggregates results, persists tally, and flags winner.
        """
        db = database.get_db()
        election = db.execute("SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
        if not election:
            flash("Election not found.", "danger")
            return redirect(url_for('admin_dashboard'))

        if election['status'] != 'closed':
            flash("Tallying can ONLY be executed after the election has been officially CLOSED.", "danger")
            return redirect(url_for('admin_dashboard'))

        existing_tally = db.execute("SELECT * FROM tally_results WHERE election_id = ?", (election_id,)).fetchone()
        parsed_results = json.loads(existing_tally['results_json']) if existing_tally else None

        if request.method == 'POST':
            # Execute Cryptographic Tallying
            # Step 1: Verify Hash Chain
            is_valid, broken_id, chain_msg, _ = crypto_utils.verify_chain(election_id, db)
            if not is_valid:
                database.log_audit(
                    db,
                    'TAMPER_ALERT_CHAIN',
                    f"CRITICAL: Hash chain verification failed for election #{election_id} at ballot #{broken_id}! {chain_msg}",
                    user_id=session['user_id'],
                    ip=request.remote_addr
                )
                flash(f"CRITICAL INTEGRITY FAILURE: Hash chain tampered at ballot #{broken_id}! Tally aborted to prevent fraudulent count.", "danger")
                return render_template(
                    'admin/tally.html',
                    election=election,
                    existing_tally=None,
                    tamper_error=chain_msg
                )

            # Step 2: Fetch all ballots
            ballots = db.execute(
                "SELECT id, encrypted_vote, encrypted_aes_key, nonce, ballot_hash FROM ballots WHERE election_id = ? ORDER BY id ASC",
                (election_id,)
            ).fetchall()

            candidates = db.execute("SELECT id, name, party FROM candidates WHERE election_id = ?", (election_id,)).fetchall()
            cand_map = {c['id']: {'name': c['name'], 'party': c['party'], 'votes': 0} for c in candidates}

            # Decrypt private key
            try:
                priv_key = crypto_utils.load_private_key()
            except Exception as e:
                flash(f"Error loading RSA Private Key: {e}", "danger")
                return render_template('admin/tally.html', election=election, existing_tally=existing_tally, parsed_results=parsed_results)

            total_valid_votes = 0
            decrypted_ballots_audit = []

            for b in ballots:
                try:
                    vote_data = crypto_utils.decrypt_vote(
                        encrypted_vote_b64=b['encrypted_vote'],
                        encrypted_aes_key_b64=b['encrypted_aes_key'],
                        nonce_b64=b['nonce'],
                        private_key=priv_key
                    )
                except crypto_utils.TamperError as e:
                    database.log_audit(
                        db,
                        'TAMPER_ALERT_GCM',
                        f"CRITICAL: Tamper detected during AES-GCM decryption of ballot #{b['id']}: {e}",
                        user_id=session['user_id'],
                        ip=request.remote_addr
                    )
                    flash(f"CRITICAL SECURITY ALERT: Ballot #{b['id']} failed AES-GCM authentication tag check: {e}. Tallying aborted!", "danger")
                    return render_template(
                        'admin/tally.html',
                        election=election,
                        existing_tally=None,
                        tamper_error=str(e)
                    )

                cand_id = vote_data.get('candidate_id')
                if cand_id in cand_map:
                    cand_map[cand_id]['votes'] += 1
                    total_valid_votes += 1

                decrypted_ballots_audit.append({
                    'ballot_id': b['id'],
                    'ballot_hash': b['ballot_hash'],
                    'timestamp': vote_data.get('timestamp')
                })

            # Calculate percentages and determine winner
            results_list = []
            winner = None
            max_votes = -1

            for c_id, c_data in cand_map.items():
                pct = round((c_data['votes'] / total_valid_votes * 100), 2) if total_valid_votes > 0 else 0
                results_list.append({
                    'candidate_id': c_id,
                    'name': c_data['name'],
                    'party': c_data['party'],
                    'votes': c_data['votes'],
                    'percentage': pct
                })
                if c_data['votes'] > max_votes and c_data['votes'] > 0:
                    max_votes = c_data['votes']
                    winner = c_data

            # Sort by vote count descending
            results_list.sort(key=lambda x: x['votes'], reverse=True)

            results_payload = {
                'election_id': election_id,
                'total_votes': total_valid_votes,
                'candidates': results_list,
                'decrypted_at': datetime.now(timezone.utc).isoformat()
            }

            results_json = json.dumps(results_payload)

            # Insert or replace tally results
            cursor = db.cursor()
            cursor.execute(
                """INSERT INTO tally_results (election_id, results_json, total_votes, winner_name, winner_party)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(election_id) DO UPDATE SET
                   results_json=excluded.results_json,
                   total_votes=excluded.total_votes,
                   winner_name=excluded.winner_name,
                   winner_party=excluded.winner_party,
                   tallied_at=CURRENT_TIMESTAMP""",
                (election_id, results_json, total_valid_votes, winner['name'] if winner else 'No Votes', winner['party'] if winner else '')
            )
            database.log_audit(
                db,
                'ELECTION_TALLIED',
                f"Tally completed for election #{election_id} ({total_valid_votes} ballots decrypted). Winner: {winner['name'] if winner else 'None'}",
                user_id=session['user_id'],
                ip=request.remote_addr
            )
            db.commit()

            flash(f"Cryptographic tally complete! {total_valid_votes} ballots decrypted and verified with zero tampering.", "success")
            return redirect(url_for('admin_tally_election', election_id=election_id))

        return render_template(
            'admin/tally.html',
            election=election,
            existing_tally=existing_tally,
            parsed_results=parsed_results,
            tamper_error=None
        )

    @app.route('/admin/audit')
    @admin_required
    def admin_audit():
        """View immutable system security audit log."""
        db = database.get_db()
        search_query = request.args.get('q', '').strip()

        if search_query:
            audits = db.execute(
                """SELECT a.*, u.email as user_email 
                   FROM audit_log a 
                   LEFT JOIN users u ON a.user_id = u.id 
                   WHERE a.action LIKE ? OR a.details LIKE ? OR a.ip LIKE ? OR u.email LIKE ?
                   ORDER BY a.created_at DESC LIMIT 150""",
                (f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%")
            ).fetchall()
        else:
            audits = db.execute(
                """SELECT a.*, u.email as user_email 
                   FROM audit_log a 
                   LEFT JOIN users u ON a.user_id = u.id 
                   ORDER BY a.created_at DESC LIMIT 150"""
            ).fetchall()

        return render_template('admin/audit.html', audits=audits, search_query=search_query)

    return app


if __name__ == '__main__':
    app = create_app()
    print("==================================================================")
    print("  SecureVote: Secure Online Voting Data System (RSA-2048 + AES-GCM)")
    print("  Application running at: http://127.0.0.1:5000")
    print("==================================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)

