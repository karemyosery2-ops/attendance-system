"""
============================================================
 Local Web Attendance System
 ------------------------------------------------------------
 A fully offline Flask + SQLite attendance registration app.
 Designed to run on a laptop connected to a local (offline)
 Wi-Fi router. Students connect via phone, scan a QR code
 pointing to http://<LAPTOP_LOCAL_IP>/ and register attendance.

 Architecture (v2 — Sign-In / Sign-Up):
   • users table          : unique student accounts
   • attendance_logs table: each class attendance event

 Anti-cheating strategy (hybrid, works 100% offline):
   1) IP+MAC lock  : both address types are checked against
                     attendance_logs — one submission per device
                     per COOLDOWN window (configurable).
   2) Session lock : Flask server-side session tracks the
                     authenticated student to power the dashboard.

 Teacher tools (localhost only, /admin/*):
   • /admin/list           full log + daily summary
   • /admin/export.csv     CSV export for a chosen date range
   • /admin/settings       change the anti-cheat block window
   • /admin/student/add_manual   manual registration (bypass)

 Developed by Karem Yousry
 Run:  python app.py   (requires admin/root for port 80)
============================================================
"""

import csv
import io
import json
import os
import re
import secrets
import sqlite3
import subprocess
from datetime import datetime, timedelta, date

from flask import (
    Flask,
    Response,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.utils import secure_filename

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attendance.db")
DEFAULT_COOLDOWN_HOURS = 24
SECRET_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "downloads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Expose Python's enumerate to Jinja2 templates
app.jinja_env.globals["enumerate"] = enumerate


def _load_or_create_secret_key() -> str:
    """Persist a random secret key on disk so sessions survive server restarts."""
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r") as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w") as fh:
        fh.write(key)
    return key


app.config["SECRET_KEY"] = _load_or_create_secret_key()

# Serializer for legacy cookie compatibility (kept for smooth migration)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="attendance-lock")


# ------------------------------------------------------------------
# Database helpers
# ------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    """Open one SQLite connection per request (stored on flask.g)."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    """Close the DB connection at the end of every request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """
    Create tables if they do not exist.
    Migrates old `students` table data → `users` + `attendance_logs`.
    Called automatically on startup.
    """
    with sqlite3.connect(DATABASE) as db:
        db.row_factory = sqlite3.Row

        # --- New schema ---
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT    NOT NULL,
                phone      TEXT    NOT NULL,
                email      TEXT    NOT NULL UNIQUE,
                created_at TEXT    NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS attendance_logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                ip_address      TEXT    NOT NULL DEFAULT '',
                mac_address     TEXT    NOT NULL DEFAULT '',
                submission_time TEXT    NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL,
                action     TEXT NOT NULL,
                details    TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT ''
            )
        """)
        db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            ("cooldown_hours", str(DEFAULT_COOLDOWN_HOURS)),
        )

        # --- Module 1: Quizzes & Evaluation ---
        db.execute("""
            CREATE TABLE IF NOT EXISTS quizzes (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                title        TEXT    NOT NULL,
                is_mandatory INTEGER NOT NULL DEFAULT 0,
                created_at   TEXT    NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS questions (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                quiz_id        INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
                type           TEXT    NOT NULL CHECK(type IN ('MCQ','Essay')),
                question_text  TEXT    NOT NULL,
                options_json   TEXT    NOT NULL DEFAULT '[]',
                correct_answer TEXT    NOT NULL DEFAULT '',
                points         INTEGER NOT NULL DEFAULT 1
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS quiz_attempts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                quiz_id     INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
                total_score INTEGER NOT NULL DEFAULT 0,
                submitted_at TEXT   NOT NULL,
                UNIQUE(user_id, quiz_id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS quiz_answers (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_id  INTEGER NOT NULL REFERENCES quiz_attempts(id) ON DELETE CASCADE,
                question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
                answer_text TEXT    NOT NULL DEFAULT '',
                score       INTEGER NOT NULL DEFAULT 0
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_qa_attempt ON quiz_answers(attempt_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_attempt_user ON quiz_attempts(user_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_q_quiz ON questions(quiz_id)")

        # --- Module 2: Admin IP whitelist ---
        db.execute("""
            CREATE TABLE IF NOT EXISTS admin_ips (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT    NOT NULL UNIQUE,
                added_at   TEXT    NOT NULL
            )
        """)

        # --- Add private_admin_mark column to users if missing ---
        cols = [r["name"] for r in db.execute("PRAGMA table_info(users)").fetchall()]
        if "private_admin_mark" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN private_admin_mark TEXT")


        # --- Migrate old `students` table if it exists ---
        has_students = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='students'"
        ).fetchone()
        if has_students:
            old_rows = db.execute(
                "SELECT name, phone, email, ip_address, mac_address, submission_time FROM students ORDER BY id ASC"
            ).fetchall()
            for row in old_rows:
                # Try to get mac_address (may not exist in old schema)
                try:
                    mac = row["mac_address"]
                except (IndexError, sqlite3.OperationalError):
                    mac = ""
                existing_user = db.execute(
                    "SELECT id FROM users WHERE email = ?", (row["email"],)
                ).fetchone()
                if existing_user:
                    user_id = existing_user["id"]
                else:
                    db.execute(
                        "INSERT INTO users (name, phone, email, created_at) VALUES (?,?,?,?)",
                        (row["name"], row["phone"], row["email"], row["submission_time"]),
                    )
                    user_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                # Only migrate log if not already present
                exists_log = db.execute(
                    "SELECT 1 FROM attendance_logs WHERE user_id=? AND submission_time=?",
                    (user_id, row["submission_time"]),
                ).fetchone()
                if not exists_log:
                    db.execute(
                        "INSERT INTO attendance_logs (user_id, ip_address, mac_address, submission_time) VALUES (?,?,?,?)",
                        (user_id, row["ip_address"], mac, row["submission_time"]),
                    )
            db.execute("DROP TABLE IF EXISTS students")
            db.commit()
        else:
            db.commit()


def log_action(action: str, details: str = "") -> None:
    """Append one row to the audit log for the current admin request."""
    get_db().execute(
        "INSERT INTO audit_log (ts, action, details, ip_address) VALUES (?, ?, ?, ?)",
        (
            datetime.now().isoformat(sep=" ", timespec="seconds"),
            action,
            details,
            request.remote_addr or "",
        ),
    )
    get_db().commit()


# ------------------------------------------------------------------
# Settings accessors
# ------------------------------------------------------------------
def get_cooldown_hours() -> int:
    try:
        row = get_db().execute(
            "SELECT value FROM settings WHERE key = ?", ("cooldown_hours",)
        ).fetchone()
        if row:
            hours = int(row["value"])
            if 1 <= hours <= 24 * 30:
                return hours
    except (ValueError, sqlite3.Error):
        pass
    return DEFAULT_COOLDOWN_HOURS


def set_cooldown_hours(hours: int) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        ("cooldown_hours", str(hours)),
    )
    db.commit()


# ------------------------------------------------------------------
# Anti-cheating helpers (IP + MAC dual lock)
# ------------------------------------------------------------------
def get_mac_address(ip: str) -> str:
    """Extract MAC address for an IP on the local subnet via ARP."""
    try:
        if os.name == "nt":
            output = subprocess.check_output(
                ["arp", "-a", ip], text=True, stderr=subprocess.STDOUT
            )
        else:
            output = subprocess.check_output(
                ["arp", "-n", ip], text=True, stderr=subprocess.STDOUT
            )
        match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        if match:
            return match.group(0).replace("-", ":").upper()
    except Exception:
        pass
    return ""


def device_already_attended(ip: str, mac: str, exclude_user_id: int = None) -> bool:
    """
    Return True if this IP or MAC already has an attendance_log within
    the current cooldown window. Optionally excludes one user (to allow
    re-checking after reset).
    """
    hours = get_cooldown_hours()
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat(sep=" ")
    db = get_db()

    exclude_clause = "AND user_id != ?" if exclude_user_id else ""
    params_ip = [ip, cutoff]
    params_mac = [mac, cutoff]
    if exclude_user_id:
        params_ip.append(exclude_user_id)
        params_mac.append(exclude_user_id)

    if ip:
        row = db.execute(
            f"SELECT 1 FROM attendance_logs WHERE ip_address=? AND ip_address!='' "
            f"AND submission_time>? {exclude_clause} LIMIT 1",
            params_ip,
        ).fetchone()
        if row:
            return True

    if mac:
        row = db.execute(
            f"SELECT 1 FROM attendance_logs WHERE mac_address=? AND mac_address!='' "
            f"AND submission_time>? {exclude_clause} LIMIT 1",
            params_mac,
        ).fetchone()
        if row:
            return True

    return False


def user_already_attended_today(user_id: int) -> bool:
    """Return True if this specific user already has a log within the cooldown."""
    hours = get_cooldown_hours()
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat(sep=" ")
    row = get_db().execute(
        "SELECT 1 FROM attendance_logs WHERE user_id=? AND submission_time>? LIMIT 1",
        (user_id, cutoff),
    ).fetchone()
    return row is not None


LOCAL_ADMIN_IPS = ("127.0.0.1", "::1")


def _ip_is_whitelisted(ip: str) -> bool:
    if not ip:
        return False
    if ip in LOCAL_ADMIN_IPS:
        return True
    try:
        row = get_db().execute(
            "SELECT 1 FROM admin_ips WHERE ip_address = ? LIMIT 1", (ip,)
        ).fetchone()
        return row is not None
    except sqlite3.Error:
        return False


def _admin_only():
    if not _ip_is_whitelisted(request.remote_addr):
        return "غير مسموح — هذه الصفحة للمعلم فقط.", 403
    return None


def is_admin_request() -> bool:
    """Return True if the request originates from the teacher or a whitelisted assistant IP."""
    return _ip_is_whitelisted(request.remote_addr)



# ------------------------------------------------------------------
# Public routes — Student Authentication & Dashboard
# ------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    """Show auth page, or redirect to dashboard if already in session."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/api/check_email", methods=["POST"])
def api_check_email():
    """
    AJAX: Check if an email exists in `users`.
    Returns JSON: {exists: bool, name: str|null}
    """
    email = (request.form.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"error": "invalid_email"}), 400

    row = get_db().execute(
        "SELECT name FROM users WHERE email = ?", (email,)
    ).fetchone()
    if row:
        return jsonify({"exists": True, "name": row["name"]})
    return jsonify({"exists": False, "name": None})


@app.route("/submit", methods=["POST"])
def submit():
    """
    Unified Sign-In / Sign-Up + attendance logging handler.

    Sign-In:  email exists  → verify device not blocked → log attendance
    Sign-Up:  email is new  → validate name+phone → create user → log attendance
    Both: set session, redirect to /dashboard
    
    ADMIN BYPASS: when called from localhost (127.0.0.1 / ::1), all
    duplicate IP/MAC and same-day checks are skipped.
    """
    ip = request.remote_addr
    mac = get_mac_address(ip)
    email = (request.form.get("email") or "").strip().lower()
    mode = request.form.get("mode", "signin")  # 'signin' or 'signup'
    is_local_admin = is_admin_request()

    # --- Basic email validation ---
    if not email or "@" not in email or "." not in email.split("@")[-1] or len(email) > 255:
        return render_template("index.html", errors=["البريد الإلكتروني غير صالح"], email=email)

    db = get_db()
    existing_user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    # ---- SIGN-IN FLOW ----
    if existing_user:
        user_id = existing_user["id"]

        # منع تسجيل نفس الطالب أكثر من مرة في نفس اليوم
        # (يتم تجاوز هذا للمعلم عند الاختبار من الجهاز المحلي)
        if not is_local_admin:
            today = date.today().isoformat()

            already_today = db.execute(""" 
                SELECT 1
                FROM attendance_logs
                WHERE user_id = ?
                AND DATE(submission_time) = ?
                LIMIT 1
            """, (user_id, today)).fetchone()

            if already_today:
                session["user_id"] = user_id
                session["user_name"] = existing_user["name"]
                return redirect(url_for("dashboard", already=1))

            # Check: is this device already tied to ANOTHER user's attendance?
            if device_already_attended(ip, mac, exclude_user_id=user_id):
                return render_template("blocked.html",
                                       reason="تم استخدام هذا الجهاز لتسجيل حضور طالب آخر بالفعل اليوم.")

        # All clear — log attendance
        db.execute(
            "INSERT INTO attendance_logs (user_id, ip_address, mac_address, submission_time) VALUES (?,?,?,?)",
            (user_id, ip, mac, datetime.now().isoformat(sep=" ", timespec="seconds")),
        )
        db.commit()
        session["user_id"] = user_id
        session["user_name"] = existing_user["name"]
        return redirect(url_for("dashboard"))

    # ---- SIGN-UP FLOW ----
    if mode != "signup":
        # Frontend should not reach here, but handle gracefully
        return render_template("index.html",
                               errors=["البريد الإلكتروني غير مسجل. يرجى إكمال بيانات التسجيل."],
                               email=email, show_signup=True)

    name = (request.form.get("name") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    errors = []
    if not (2 <= len(name) <= 100):
        errors.append("الاسم يجب أن يكون بين 2 و 100 حرف")
    digits = phone.replace(" ", "").replace("-", "")
    if not ((digits.startswith("+") and digits[1:].isdigit()) or digits.isdigit()) or not (
        8 <= len(digits.lstrip("+")) <= 15
    ):
        errors.append("رقم الهاتف غير صالح")

    if errors:
        return render_template("index.html",
                               errors=errors, email=email, name=name, phone=phone,
                               show_signup=True)

    # Check: is this device already used today (before creating account)?
    # (يتم تجاوز هذا للمعلم عند الاختبار من الجهاز المحلي)
    if not is_local_admin and device_already_attended(ip, mac):
        return render_template("blocked.html",
                               reason="تم استخدام هذا الجهاز لتسجيل حضور طالب آخر بالفعل اليوم.")

    # Create user account
    now_str = datetime.now().isoformat(sep=" ", timespec="seconds")
    cursor = db.execute(
        "INSERT INTO users (name, phone, email, created_at) VALUES (?,?,?,?)",
        (name, phone, email, now_str),
    )
    user_id = cursor.lastrowid

    # Log attendance
    db.execute(
        "INSERT INTO attendance_logs (user_id, ip_address, mac_address, submission_time) VALUES (?,?,?,?)",
        (user_id, ip, mac, now_str),
    )
    db.commit()

    session["user_id"] = user_id
    session["user_name"] = name
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    """Personalized student dashboard — requires active session."""
    if "user_id" not in session:
        return redirect(url_for("index"))

    user_id = session["user_id"]
    db = get_db()

    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("index"))

    logs = db.execute(
        "SELECT submission_time, ip_address FROM attendance_logs "
        "WHERE user_id=? ORDER BY submission_time DESC",
        (user_id,),
    ).fetchall()

    total_attended = len(logs)
    last_attendance = logs[0]["submission_time"] if logs else "—"
    already = request.args.get("already") == "1"

    has_material = os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], "handout.pdf"))
    
    # Get all downloadable materials
    materials = []
    if os.path.exists(app.config["UPLOAD_FOLDER"]):
        for fname in os.listdir(app.config["UPLOAD_FOLDER"]):
            if fname.lower().endswith(".pdf"):
                materials.append(fname)

    # Quizzes + this student's attempts
    quizzes = db.execute(
        """SELECT q.id, q.title, q.is_mandatory,
                  (SELECT COUNT(*) FROM questions WHERE quiz_id=q.id) AS q_count,
                  a.total_score AS my_score,
                  a.submitted_at AS my_submitted_at
           FROM quizzes q
           LEFT JOIN quiz_attempts a ON a.quiz_id=q.id AND a.user_id=?
           ORDER BY q.is_mandatory DESC, q.created_at DESC""",
        (user_id,),
    ).fetchall()

    return render_template(
        "dashboard.html",
        user=user,
        logs=logs,
        total_attended=total_attended,
        last_attendance=last_attendance,
        has_material=has_material,
        materials=materials,
        already=already,
        cooldown_hours=get_cooldown_hours(),
        quizzes=quizzes,
    )



@app.route("/logout")
def logout():
    """Clear student session and redirect to home."""
    session.clear()
    return redirect(url_for("index"))


# ------------------------------------------------------------------
# Admin routes (localhost only)
# ------------------------------------------------------------------
def _parse_iso_date(param: str):
    raw = (request.args.get(param) or "").strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date().isoformat()
    except ValueError:
        return "__INVALID__"


@app.route("/admin/list")
def admin_list():
    denied = _admin_only()
    if denied:
        return denied

    db = get_db()

    d_from = _parse_iso_date("from")
    d_to = _parse_iso_date("to")
    date_error = None
    if d_from == "__INVALID__" or d_to == "__INVALID__":
        date_error = "صيغة التاريخ غير صحيحة، استخدم YYYY-MM-DD."
        d_from = None if d_from == "__INVALID__" else d_from
        d_to = None if d_to == "__INVALID__" else d_to

    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    try:
        per_page = int(request.args.get("per_page", "25"))
    except ValueError:
        per_page = 25
    per_page = max(10, min(200, per_page))

    # Join users + latest attendance log per user + total count
    clauses, params = [], []
    if d_from:
        clauses.append("substr(al.submission_time, 1, 10) >= ?")
        params.append(d_from)
    if d_to:
        clauses.append("substr(al.submission_time, 1, 10) <= ?")
        params.append(d_to)
    where = ("AND " + " AND ".join(clauses)) if clauses else ""

    total_filtered = db.execute(
        f"""SELECT COUNT(DISTINCT u.id) AS c
            FROM users u
            JOIN attendance_logs al ON al.user_id = u.id
            WHERE 1=1 {where}""",
        params,
    ).fetchone()["c"]

    total_pages = max(1, (total_filtered + per_page - 1) // per_page)
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    rows = db.execute(
        f"""SELECT u.id, u.name, u.phone, u.email,
                   al.ip_address, al.mac_address,
                   MAX(al.submission_time) AS submission_time,
                   COUNT(DISTINCT DATE(al.submission_time)) AS attendance_count
            FROM users u
            JOIN attendance_logs al ON al.user_id = u.id
            WHERE 1=1 {where}
            GROUP BY u.id
            ORDER BY MAX(al.submission_time) DESC
            LIMIT ? OFFSET ?""",
        [*params, per_page, offset],
    ).fetchall()

    # Daily summary
    today_prefix = date.today().isoformat()
    summary_row = db.execute(
        """SELECT COUNT(*) AS total,
                  COUNT(DISTINCT al.ip_address) AS unique_devices,
                  MAX(al.submission_time) AS last_time_today
           FROM attendance_logs al
           WHERE substr(al.submission_time, 1, 10) = ?""",
        (today_prefix,),
    ).fetchone()

    last_overall = db.execute(
        "SELECT MAX(submission_time) AS t FROM attendance_logs"
    ).fetchone()

    summary = {
        "date": today_prefix,
        "total": summary_row["total"] or 0,
        "unique_devices": summary_row["unique_devices"] or 0,
        "last_today": summary_row["last_time_today"] or "—",
        "last_overall": last_overall["t"] or "—",
    }

    audit_rows = db.execute(
        "SELECT ts, action, details, ip_address FROM audit_log ORDER BY id DESC LIMIT 10"
    ).fetchall()

    return render_template(
        "admin.html",
        rows=rows,
        summary=summary,
        cooldown_hours=get_cooldown_hours(),
        default_from=today_prefix,
        default_to=today_prefix,
        filter_from=d_from or "",
        filter_to=d_to or "",
        date_error=date_error,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_filtered=total_filtered,
        audit_rows=audit_rows,
        has_material=os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], "handout.pdf")),
    )


@app.route("/admin/export.csv")
def admin_export_csv():
    denied = _admin_only()
    if denied:
        return denied

    d_from = _parse_iso_date("from")
    d_to = _parse_iso_date("to")
    if d_from == "__INVALID__" or d_to == "__INVALID__":
        return "صيغة التاريخ غير صحيحة، استخدم YYYY-MM-DD.", 400

    clauses, params = [], []
    if d_from:
        clauses.append("substr(al.submission_time, 1, 10) >= ?")
        params.append(d_from)
    if d_to:
        clauses.append("substr(al.submission_time, 1, 10) <= ?")
        params.append(d_to)
    where = ("AND " + " AND ".join(clauses)) if clauses else ""

    rows = get_db().execute(
        f"""SELECT u.id, u.name, u.phone, u.email,
                   al.ip_address, al.mac_address, al.submission_time
            FROM users u
            JOIN attendance_logs al ON al.user_id = u.id
            WHERE 1=1 {where}
            ORDER BY al.submission_time ASC""",
        params,
    ).fetchall()

    buf = io.StringIO()
    buf.write("\ufeff")
    writer = csv.writer(buf)
    writer.writerow(["id", "name", "phone", "email", "ip_address", "mac_address", "submission_time"])
    for r in rows:
        writer.writerow([r["id"], r["name"], r["phone"], r["email"],
                         r["ip_address"], r["mac_address"], r["submission_time"]])

    filename = f"attendance_{d_from or 'all'}_to_{d_to or 'all'}.csv"
    log_action("export_csv", f"range={d_from or '*'}..{d_to or '*'} rows={len(rows)}")

    return Response(
        buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/admin/student/<int:id>/edit", methods=["POST"])
def admin_edit_student(id):
    denied = _admin_only()
    if denied:
        return denied

    name = (request.form.get("name") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    email = (request.form.get("email") or "").strip()

    if not name or not phone or not email:
        return jsonify({"success": False, "error": "جميع الحقول مطلوبة."}), 400

    db = get_db()
    db.execute(
        "UPDATE users SET name=?, phone=?, email=? WHERE id=?",
        (name, phone, email, id),
    )
    db.commit()
    log_action("edit_student", f"user_id={id} name={name}")
    return jsonify({"success": True})


@app.route("/admin/student/<int:id>/delete", methods=["POST"])
def admin_delete_student(id):
    denied = _admin_only()
    if denied:
        return denied

    db = get_db()
    db.execute("DELETE FROM attendance_logs WHERE user_id=?", (id,))
    db.execute("DELETE FROM users WHERE id=?", (id,))
    db.commit()
    log_action("delete_student", f"user_id={id}")
    return jsonify({"success": True})


@app.route("/admin/student/<int:id>/reset_ip", methods=["POST"])
def admin_reset_student_ip(id):
    """
    Reset: delete only TODAY's attendance logs for this user so they
    can attend again. Keeps historical records intact.
    """
    denied = _admin_only()
    if denied:
        return denied

    hours = get_cooldown_hours()
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat(sep=" ")
    db = get_db()
    db.execute(
        "DELETE FROM attendance_logs WHERE user_id=? AND submission_time>?",
        (id, cutoff),
    )
    db.commit()
    log_action("reset_student_ip", f"user_id={id}")
    return jsonify({"success": True})


@app.route("/admin/reset_all", methods=["POST"])
def admin_reset_all():
    """Delete ALL attendance logs within the current cooldown window for all users."""
    denied = _admin_only()
    if denied:
        return denied

    hours = get_cooldown_hours()
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat(sep=" ")
    db = get_db()
    db.execute("DELETE FROM attendance_logs WHERE submission_time>?", (cutoff,))
    db.commit()
    log_action("reset_all_ips", "Cleared all current-window attendance logs")
    return jsonify({"success": True})


@app.route("/admin/student/add_manual", methods=["POST"])
def admin_add_manual():
    """
    Manual student registration by the teacher.
    BYPASSES all anti-cheat checks (IP/MAC lock, same-day duplicate).
    Creates user if email is new, always logs a fresh attendance entry.
    """
    denied = _admin_only()
    if denied:
        return denied

    name = (request.form.get("name") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    email = (request.form.get("email") or "").strip().lower()

    errors = []
    if not (2 <= len(name) <= 100):
        errors.append("الاسم يجب أن يكون بين 2 و 100 حرف")
    digits = phone.replace(" ", "").replace("-", "")
    if not ((digits.startswith("+") and digits[1:].isdigit()) or digits.isdigit()) or not (
        8 <= len(digits.lstrip("+")) <= 15
    ):
        errors.append("رقم الهاتف غير صالح")
    if not email or "@" not in email or "." not in email.split("@")[-1] or len(email) > 255:
        errors.append("البريد الإلكتروني غير صالح")

    if errors:
        return jsonify({"success": False, "errors": errors}), 400

    db = get_db()
    now_str = datetime.now().isoformat(sep=" ", timespec="seconds")

    # Find existing user or create new one
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        user_id = existing["id"]
        is_new = False
    else:
        cursor = db.execute(
            "INSERT INTO users (name, phone, email, created_at) VALUES (?,?,?,?)",
            (name, phone, email, now_str),
        )
        user_id = cursor.lastrowid
        is_new = True

    # Log attendance immediately — no anti-cheat gates
    ip = request.remote_addr or "127.0.0.1"
    mac = get_mac_address(ip) if ip not in ("127.0.0.1", "::1") else ""

    db.execute(
        "INSERT INTO attendance_logs (user_id, ip_address, mac_address, submission_time) VALUES (?,?,?,?)",
        (user_id, ip, mac, now_str),
    )
    db.commit()

    log_action("manual_register", f"user_id={user_id} name={name} email={email} new={is_new}")

    return jsonify({
        "success": True,
        "user_id": user_id,
        "name": name,
        "email": email,
        "is_new": is_new,
    })


@app.route("/admin/upload_material", methods=["POST"])
def admin_upload_material():
    denied = _admin_only()
    if denied:
        return denied

    if "file" not in request.files:
        return redirect(url_for("admin_list"))

    file = request.files["file"]
    if file.filename == "":
        return redirect(url_for("admin_list"))

    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        log_action("upload_material", f"Uploaded {filename}")

    return redirect(url_for("admin_list"))


@app.route("/admin/delete_material", methods=["POST"])
def admin_delete_material():
    denied = _admin_only()
    if denied:
        return denied

    filename = request.form.get("filename", "handout.pdf")
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(filename))
    if os.path.exists(file_path):
        os.remove(file_path)
        log_action("delete_material", f"Deleted {filename}")

    return redirect(url_for("admin_list"))


@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    denied = _admin_only()
    if denied:
        return denied

    error = None
    if request.method == "POST":
        raw = (request.form.get("cooldown_hours") or "").strip()
        try:
            hours = int(raw)
            if not (1 <= hours <= 24 * 30):
                raise ValueError
            old_hours = get_cooldown_hours()
            set_cooldown_hours(hours)
            if old_hours != hours:
                log_action("settings_change", f"cooldown_hours: {old_hours} -> {hours}")
            return redirect(url_for("admin_settings", saved=1))
        except ValueError:
            error = "أدخل عدد ساعات صحيح بين 1 و 720."

    return render_template(
        "settings.html",
        cooldown_hours=get_cooldown_hours(),
        default_hours=DEFAULT_COOLDOWN_HOURS,
        saved=request.args.get("saved") == "1",
        error=error,
    )


# ==================================================================
# Module 1 — Quizzes & Evaluation
# ==================================================================
def _recalc_attempt_score(db, attempt_id: int) -> int:
    total = db.execute(
        "SELECT COALESCE(SUM(score),0) AS s FROM quiz_answers WHERE attempt_id=?",
        (attempt_id,),
    ).fetchone()["s"]
    db.execute("UPDATE quiz_attempts SET total_score=? WHERE id=?", (total, attempt_id))
    return total


# ---- Admin: quiz builder ----
@app.route("/admin/quizzes", methods=["GET", "POST"])
def admin_quizzes():
    denied = _admin_only()
    if denied:
        return denied
    db = get_db()
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        is_mand = 1 if request.form.get("is_mandatory") else 0
        if not title:
            return redirect(url_for("admin_quizzes"))
        db.execute(
            "INSERT INTO quizzes (title, is_mandatory, created_at) VALUES (?,?,?)",
            (title, is_mand, datetime.now().isoformat(sep=" ", timespec="seconds")),
        )
        db.commit()
        log_action("quiz_create", f"title={title}")
        return redirect(url_for("admin_quizzes"))

    quizzes = db.execute(
        """SELECT q.*,
                  (SELECT COUNT(*) FROM questions WHERE quiz_id=q.id) AS q_count,
                  (SELECT COUNT(*) FROM quiz_attempts WHERE quiz_id=q.id) AS attempts
           FROM quizzes q ORDER BY q.created_at DESC"""
    ).fetchall()
    return render_template("admin_quizzes.html", quizzes=quizzes)


@app.route("/admin/quizzes/<int:qid>", methods=["GET", "POST"])
def admin_quiz_builder(qid):
    denied = _admin_only()
    if denied:
        return denied
    db = get_db()
    quiz = db.execute("SELECT * FROM quizzes WHERE id=?", (qid,)).fetchone()
    if not quiz:
        return "الاختبار غير موجود", 404

    if request.method == "POST":
        qtype = request.form.get("type", "MCQ")
        text = (request.form.get("question_text") or "").strip()
        points_raw = (request.form.get("points") or "1").strip()
        try:
            points = max(0, int(points_raw))
        except ValueError:
            points = 1
        if not text:
            return redirect(url_for("admin_quiz_builder", qid=qid))
        if qtype == "MCQ":
            opts = [
                (request.form.get(f"opt{i}") or "").strip() for i in range(1, 5)
            ]
            opts = [o for o in opts if o]
            correct = (request.form.get("correct") or "").strip()
            if len(opts) < 2 or correct not in opts:
                return redirect(url_for("admin_quiz_builder", qid=qid))
            db.execute(
                "INSERT INTO questions (quiz_id, type, question_text, options_json, correct_answer, points) VALUES (?,?,?,?,?,?)",
                (qid, "MCQ", text, json.dumps(opts, ensure_ascii=False), correct, points),
            )
        else:
            # Essay — default 0 points auto-graded (admin grades manually)
            db.execute(
                "INSERT INTO questions (quiz_id, type, question_text, options_json, correct_answer, points) VALUES (?,?,?,?,?,?)",
                (qid, "Essay", text, "[]", "", points),
            )
        db.commit()
        log_action("quiz_add_question", f"quiz_id={qid} type={qtype}")
        return redirect(url_for("admin_quiz_builder", qid=qid))

    questions = db.execute(
        "SELECT * FROM questions WHERE quiz_id=? ORDER BY id ASC", (qid,)
    ).fetchall()
    q_list = []
    for q in questions:
        d = dict(q)
        try:
            d["options"] = json.loads(d["options_json"] or "[]")
        except json.JSONDecodeError:
            d["options"] = []
        q_list.append(d)
    return render_template("admin_quiz_builder.html", quiz=quiz, questions=q_list)


@app.route("/admin/quizzes/<int:qid>/toggle_mandatory", methods=["POST"])
def admin_quiz_toggle(qid):
    denied = _admin_only()
    if denied:
        return denied
    db = get_db()
    db.execute("UPDATE quizzes SET is_mandatory = 1 - is_mandatory WHERE id=?", (qid,))
    db.commit()
    return jsonify({"success": True})


@app.route("/admin/quizzes/<int:qid>/delete", methods=["POST"])
def admin_quiz_delete(qid):
    denied = _admin_only()
    if denied:
        return denied
    db = get_db()
    db.execute("DELETE FROM quiz_answers WHERE attempt_id IN (SELECT id FROM quiz_attempts WHERE quiz_id=?)", (qid,))
    db.execute("DELETE FROM quiz_attempts WHERE quiz_id=?", (qid,))
    db.execute("DELETE FROM questions WHERE quiz_id=?", (qid,))
    db.execute("DELETE FROM quizzes WHERE id=?", (qid,))
    db.commit()
    log_action("quiz_delete", f"quiz_id={qid}")
    return redirect(url_for("admin_quizzes"))


@app.route("/admin/question/<int:qid>/delete", methods=["POST"])
def admin_question_delete(qid):
    denied = _admin_only()
    if denied:
        return denied
    db = get_db()
    row = db.execute("SELECT quiz_id FROM questions WHERE id=?", (qid,)).fetchone()
    if not row:
        return redirect(url_for("admin_quizzes"))
    quiz_id = row["quiz_id"]
    db.execute("DELETE FROM quiz_answers WHERE question_id=?", (qid,))
    db.execute("DELETE FROM questions WHERE id=?", (qid,))
    db.commit()
    return redirect(url_for("admin_quiz_builder", qid=quiz_id))


# ---- Student: take quiz ----
@app.route("/quiz/<int:qid>", methods=["GET", "POST"])
def student_quiz(qid):
    if "user_id" not in session:
        return redirect(url_for("index"))
    user_id = session["user_id"]
    db = get_db()
    quiz = db.execute("SELECT * FROM quizzes WHERE id=?", (qid,)).fetchone()
    if not quiz:
        return "الاختبار غير موجود", 404
    prev = db.execute(
        "SELECT * FROM quiz_attempts WHERE user_id=? AND quiz_id=?", (user_id, qid)
    ).fetchone()

    questions = db.execute(
        "SELECT * FROM questions WHERE quiz_id=? ORDER BY id ASC", (qid,)
    ).fetchall()
    q_list = []
    for q in questions:
        d = dict(q)
        try:
            d["options"] = json.loads(d["options_json"] or "[]")
        except json.JSONDecodeError:
            d["options"] = []
        q_list.append(d)

    if request.method == "POST":
        if prev:
            return redirect(url_for("student_quiz_result", qid=qid))
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        cur = db.execute(
            "INSERT INTO quiz_attempts (user_id, quiz_id, total_score, submitted_at) VALUES (?,?,0,?)",
            (user_id, qid, now),
        )
        attempt_id = cur.lastrowid
        total = 0
        for q in q_list:
            ans = (request.form.get(f"q_{q['id']}") or "").strip()
            score = 0
            if q["type"] == "MCQ" and ans and ans == q["correct_answer"]:
                score = int(q["points"] or 1)
            # Essay: default 0, admin grades later
            db.execute(
                "INSERT INTO quiz_answers (attempt_id, question_id, answer_text, score) VALUES (?,?,?,?)",
                (attempt_id, q["id"], ans, score),
            )
            total += score
        db.execute("UPDATE quiz_attempts SET total_score=? WHERE id=?", (total, attempt_id))
        db.commit()
        return redirect(url_for("student_quiz_result", qid=qid))

    return render_template(
        "quiz_take.html", quiz=quiz, questions=q_list, already=bool(prev),
    )


@app.route("/quiz/<int:qid>/result")
def student_quiz_result(qid):
    if "user_id" not in session:
        return redirect(url_for("index"))
    user_id = session["user_id"]
    db = get_db()
    quiz = db.execute("SELECT * FROM quizzes WHERE id=?", (qid,)).fetchone()
    attempt = db.execute(
        "SELECT * FROM quiz_attempts WHERE user_id=? AND quiz_id=?", (user_id, qid)
    ).fetchone()
    if not quiz or not attempt:
        return redirect(url_for("dashboard"))
    max_score = db.execute(
        "SELECT COALESCE(SUM(points),0) AS s FROM questions WHERE quiz_id=?", (qid,)
    ).fetchone()["s"]
    return render_template("quiz_result.html", quiz=quiz, attempt=attempt, max_score=max_score)


# ---- Admin: master tracker ----
@app.route("/admin/students")
def admin_students():
    denied = _admin_only()
    if denied:
        return denied
    db = get_db()
    filter_mode = request.args.get("filter", "")  # 'attended_no_quiz'
    today = date.today().isoformat()

    quizzes = db.execute("SELECT id, title FROM quizzes ORDER BY created_at ASC").fetchall()

    users = db.execute(
        """SELECT u.id, u.name, u.email, u.phone, u.private_admin_mark,
                  (SELECT COUNT(DISTINCT DATE(submission_time)) FROM attendance_logs WHERE user_id=u.id) AS attendance_count,
                  (SELECT 1 FROM attendance_logs WHERE user_id=u.id AND DATE(submission_time)=? LIMIT 1) AS attended_today
           FROM users u ORDER BY u.name ASC""",
        (today,),
    ).fetchall()

    scores_raw = db.execute(
        "SELECT user_id, quiz_id, total_score FROM quiz_attempts"
    ).fetchall()
    score_map = {}
    for r in scores_raw:
        score_map.setdefault(r["user_id"], {})[r["quiz_id"]] = r["total_score"]

    rows = []
    for u in users:
        s = score_map.get(u["id"], {})
        took_any_today = False
        for q in quizzes:
            if q["id"] in s:
                # only care whether student took today's mandatory quiz — approximate
                took_any_today = True
                break
        if filter_mode == "attended_no_quiz":
            if not u["attended_today"] or took_any_today:
                continue
        rows.append({
            "user": u,
            "scores": s,
        })

    return render_template(
        "admin_students.html",
        rows=rows, quizzes=quizzes, filter_mode=filter_mode,
    )


@app.route("/admin/student/<int:uid>/profile")
def admin_student_profile(uid):
    denied = _admin_only()
    if denied:
        return denied
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not user:
        return jsonify({"error": "not_found"}), 404

    attempts = db.execute(
        """SELECT a.id, a.quiz_id, a.total_score, a.submitted_at, q.title
           FROM quiz_attempts a JOIN quizzes q ON q.id=a.quiz_id
           WHERE a.user_id=? ORDER BY a.submitted_at DESC""",
        (uid,),
    ).fetchall()

    result = {
        "user": {
            "id": user["id"], "name": user["name"], "email": user["email"],
            "phone": user["phone"],
            "private_admin_mark": user["private_admin_mark"] or "",
        },
        "attempts": [],
    }
    for a in attempts:
        answers = db.execute(
            """SELECT ans.id, ans.question_id, ans.answer_text, ans.score,
                      q.type, q.question_text, q.correct_answer, q.points
               FROM quiz_answers ans JOIN questions q ON q.id=ans.question_id
               WHERE ans.attempt_id=? ORDER BY ans.id ASC""",
            (a["id"],),
        ).fetchall()
        result["attempts"].append({
            "attempt_id": a["id"],
            "quiz_id": a["quiz_id"],
            "title": a["title"],
            "total_score": a["total_score"],
            "submitted_at": a["submitted_at"],
            "answers": [dict(x) for x in answers],
        })
    return jsonify(result)


@app.route("/admin/student/<int:uid>/grade_essay", methods=["POST"])
def admin_grade_essay(uid):
    denied = _admin_only()
    if denied:
        return denied
    try:
        answer_id = int(request.form.get("answer_id"))
        score = int(request.form.get("score"))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "invalid"}), 400
    db = get_db()
    row = db.execute(
        "SELECT attempt_id FROM quiz_answers WHERE id=?", (answer_id,)
    ).fetchone()
    if not row:
        return jsonify({"success": False, "error": "not_found"}), 404
    db.execute("UPDATE quiz_answers SET score=? WHERE id=?", (score, answer_id))
    total = _recalc_attempt_score(db, row["attempt_id"])
    db.commit()
    log_action("grade_essay", f"user_id={uid} answer_id={answer_id} score={score}")
    return jsonify({"success": True, "new_total": total})


@app.route("/admin/student/<int:uid>/override_score", methods=["POST"])
def admin_override_score(uid):
    denied = _admin_only()
    if denied:
        return denied
    try:
        attempt_id = int(request.form.get("attempt_id"))
        new_total = int(request.form.get("total_score"))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "invalid"}), 400
    db = get_db()
    db.execute(
        "UPDATE quiz_attempts SET total_score=? WHERE id=? AND user_id=?",
        (new_total, attempt_id, uid),
    )
    db.commit()
    log_action("override_score", f"user_id={uid} attempt_id={attempt_id} total={new_total}")
    return jsonify({"success": True, "new_total": new_total})


@app.route("/admin/student/<int:uid>/set_mark", methods=["POST"])
def admin_set_mark(uid):
    denied = _admin_only()
    if denied:
        return denied
    mark = (request.form.get("mark") or "").strip()
    db = get_db()
    db.execute(
        "UPDATE users SET private_admin_mark=? WHERE id=?",
        (mark or None, uid),
    )
    db.commit()
    log_action("set_private_mark", f"user_id={uid} len={len(mark)}")
    return jsonify({"success": True})


# ==================================================================
# Module 2 — Admin IP whitelist (main admin = localhost only)
# ==================================================================
def _main_admin_only():
    if request.remote_addr not in LOCAL_ADMIN_IPS:
        return "هذه العملية متاحة فقط للمعلم الرئيسي من الجهاز الخادم.", 403
    return None


@app.route("/admin/ips", methods=["GET"])
def admin_ips_list():
    denied = _admin_only()
    if denied:
        return denied
    ips = get_db().execute(
        "SELECT id, ip_address, added_at FROM admin_ips ORDER BY added_at DESC"
    ).fetchall()
    return render_template(
        "admin_ips.html",
        ips=ips,
        is_main_admin=(request.remote_addr in LOCAL_ADMIN_IPS),
        my_ip=request.remote_addr,
    )


@app.route("/admin/ips/add", methods=["POST"])
def admin_ips_add():
    denied = _main_admin_only()
    if denied:
        return denied
    ip = (request.form.get("ip_address") or "").strip()
    # Basic IPv4/IPv6 shape check
    if not re.match(r"^[0-9a-fA-F:.]{3,45}$", ip):
        return jsonify({"success": False, "error": "invalid_ip"}), 400
    try:
        get_db().execute(
            "INSERT INTO admin_ips (ip_address, added_at) VALUES (?, ?)",
            (ip, datetime.now().isoformat(sep=" ", timespec="seconds")),
        )
        get_db().commit()
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "error": "duplicate"}), 400
    log_action("admin_ip_add", f"ip={ip}")
    return redirect(url_for("admin_ips_list"))


@app.route("/admin/ips/<int:iid>/delete", methods=["POST"])
def admin_ips_delete(iid):
    denied = _main_admin_only()
    if denied:
        return denied
    get_db().execute("DELETE FROM admin_ips WHERE id=?", (iid,))
    get_db().commit()
    log_action("admin_ip_delete", f"id={iid}")
    return redirect(url_for("admin_ips_list"))


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=80, debug=False)

