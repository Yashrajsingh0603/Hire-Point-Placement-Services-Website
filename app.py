import os
import re
import uuid
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from werkzeug.utils import secure_filename

from database import get_db_connection


# =========================================================
# APP CONFIGURATION
# =========================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-development-secret-before-deployment"
)

app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024

UPLOAD_FOLDER = Path(app.root_path) / "static" / "uploads" / "profiles"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
REPORT_REASONS = {
    "Scam or fraudulent job",
    "Misleading information",
    "Inappropriate or abusive content",
    "Duplicate job listing",
    "Suspicious employer",
    "Other",
}


# =========================================================
# DATABASE HELPERS
# =========================================================

def get_or_create_company(cursor, company_name):
    company_name = company_name.strip()

    if not company_name:
        raise ValueError("Company name is required.")

    cursor.execute(
        """
        SELECT id
        FROM companies
        WHERE LOWER(name) = LOWER(%s)
        LIMIT 1
        """,
        (company_name,)
    )

    company = cursor.fetchone()

    if company:
        return company[0]

    cursor.execute(
        """
        INSERT INTO companies (name)
        VALUES (%s)
        RETURNING id
        """,
        (company_name,)
    )

    return cursor.fetchone()[0]


def initialize_additive_schema():
    """
    Add only missing profile/report schema.
    Existing tables and rows are not dropped.
    """
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS profile_photo VARCHAR(255)
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS job_reports (
                id SERIAL PRIMARY KEY,
                job_id INTEGER NOT NULL
                    REFERENCES jobs(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                reason VARCHAR(100) NOT NULL,
                description TEXT NOT NULL,
                status VARCHAR(30) NOT NULL DEFAULT 'Open',
                resolution_note TEXT,
                created_at TIMESTAMP WITHOUT TIME ZONE
                    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITHOUT TIME ZONE
                    NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_job_reports_status
            ON job_reports(status)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_job_reports_job_id
            ON job_reports(job_id)
            """
        )

        connection.commit()

    except Exception:
        connection.rollback()
        app.logger.exception("Database schema initialization failed")
        raise

    finally:
        cursor.close()
        connection.close()


# =========================================================
# AUTHENTICATION / AUTHORIZATION HELPERS
# =========================================================

def is_logged_in():
    return session.get("user_id") is not None


def is_admin():
    return session.get("role") == "admin"


def is_employer():
    return session.get("role") == "employer"


def admin_required():
    return is_logged_in() and is_admin()


def login_required_redirect(destination=None):
    if not is_logged_in():
        return redirect(
            url_for("login", next=destination or request.path)
        )
    return None


def safe_next_url(target):
    """
    Allow only local paths to prevent open redirects.
    """
    if not target:
        return None

    parsed = urlparse(target)

    if parsed.scheme or parsed.netloc:
        return None

    if not target.startswith("/") or target.startswith("//"):
        return None

    return target


def get_current_user():
    if not is_logged_in():
        return None

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT id, name, email, role, phone, location, bio,
                   created_at, profile_photo
            FROM users
            WHERE id = %s
            """,
            (session["user_id"],)
        )
        return cursor.fetchone()

    finally:
        cursor.close()
        connection.close()


def delete_profile_photo(filename):
    if not filename:
        return

    # Only delete a file from our own profile upload directory.
    safe_name = Path(filename).name

    if safe_name != filename:
        return

    path = UPLOAD_FOLDER / safe_name

    try:
        if path.is_file():
            path.unlink()
    except OSError:
        app.logger.warning("Could not remove profile image: %s", safe_name)


def valid_image_signature(file_bytes, extension):
    """
    Check basic file signatures rather than trusting the browser MIME type.
    """
    if extension in {".jpg", ".jpeg"}:
        return file_bytes.startswith(b"\xff\xd8\xff")

    if extension == ".png":
        return file_bytes.startswith(b"\x89PNG\r\n\x1a\n")

    if extension == ".webp":
        return (
            len(file_bytes) >= 12
            and file_bytes[:4] == b"RIFF"
            and file_bytes[8:12] == b"WEBP"
        )

    return False


def save_profile_photo(upload):
    if not upload or not upload.filename:
        return None

    original_name = secure_filename(upload.filename)
    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("Upload a JPG, PNG or WEBP image.")

    file_bytes = upload.read()

    if not file_bytes:
        raise ValueError("The selected image is empty.")

    if len(file_bytes) > 2 * 1024 * 1024:
        raise ValueError("Profile photo must be 2 MB or smaller.")

    if not valid_image_signature(file_bytes, extension):
        raise ValueError("The uploaded file is not a valid supported image.")

    new_name = f"{uuid.uuid4().hex}{extension}"
    destination = UPLOAD_FOLDER / new_name
    destination.write_bytes(file_bytes)

    return new_name


def admin_denied():
    abort(403, description="Administrator access is required.")


# =========================================================
# SHARED JOB QUERY
# =========================================================

JOB_SELECT = """
    SELECT
        jobs.id,
        jobs.title,
        companies.name,
        jobs.location,
        jobs.job_type,
        jobs.salary_min,
        jobs.salary_max,
        jobs.skills,
        jobs.experience,
        jobs.description,
        jobs.created_at
    FROM jobs
    JOIN companies ON jobs.company_id = companies.id
"""


def fetch_job(job_id):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            JOB_SELECT + " WHERE jobs.id = %s",
            (job_id,)
        )
        return cursor.fetchone()

    finally:
        cursor.close()
        connection.close()

# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    keyword = request.args.get("keyword", "").strip()
    location = request.args.get("location", "").strip()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Website statistics
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM jobs")
        job_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM companies")
        company_count = cursor.fetchone()[0]

        # Search jobs by title, skills, description, and location
        cursor.execute(
            JOB_SELECT
            + """
            WHERE (
                %s = ''
                OR jobs.title ILIKE %s
                OR COALESCE(jobs.skills, '') ILIKE %s
                OR COALESCE(jobs.description, '') ILIKE %s
            )
            AND (
                %s = ''
                OR COALESCE(jobs.location, '') ILIKE %s
            )
            ORDER BY jobs.created_at DESC NULLS LAST
            LIMIT 12
            """,
            (
                keyword,
                f"%{keyword}%",
                f"%{keyword}%",
                f"%{keyword}%",
                location,
                f"%{location}%"
            )
        )

        job_list = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "index.html",
        jobs=job_list,
        keyword=keyword,
        location=location,
        user_count=user_count,
        job_count=job_count,
        company_count=company_count
    )




# =========================================================
# JOB LISTING WITH SEARCH / FILTER / SORT
# =========================================================

@app.route("/jobs")
def jobs():
    keyword = request.args.get("keyword", "").strip()
    location = request.args.get("location", "").strip()
    job_type = request.args.get("job_type", "").strip()
    experience = request.args.get("experience", "").strip()
    sort = request.args.get("sort", "newest").strip()

    sort_options = {
        "newest": "jobs.created_at DESC NULLS LAST",
        "oldest": "jobs.created_at ASC NULLS LAST",
        "title_asc": "jobs.title ASC",
        "salary_high": "jobs.salary_max DESC NULLS LAST",
        "salary_low": "jobs.salary_min ASC NULLS LAST",
    }

    order_by = sort_options.get(sort, sort_options["newest"])

    query = JOB_SELECT + """
        WHERE (%s = '' OR jobs.title ILIKE %s
               OR COALESCE(jobs.skills, '') ILIKE %s
               OR COALESCE(jobs.description, '') ILIKE %s
               OR companies.name ILIKE %s)
          AND (%s = '' OR jobs.location ILIKE %s)
          AND (%s = '' OR jobs.job_type = %s)
          AND (%s = '' OR jobs.experience ILIKE %s)
        ORDER BY """ + order_by

    parameters = (
        keyword,
        f"%{keyword}%",
        f"%{keyword}%",
        f"%{keyword}%",
        f"%{keyword}%",
        location,
        f"%{location}%",
        job_type,
        job_type,
        experience,
        f"%{experience}%"
    )

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(query, parameters)
        job_list = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "jobs.html",
        jobs=job_list,
        keyword=keyword,
        location=location,
        job_type=job_type,
        experience=experience,
        sort=sort
    )


# =========================================================
# JOB DETAILS AND COMMENTS
# =========================================================

@app.route("/job/<int:job_id>")
def job_detail(job_id):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            JOB_SELECT + " WHERE jobs.id = %s",
            (job_id,)
        )
        job = cursor.fetchone()

        if not job:
            flash("Job not found.", "danger")
            return redirect(url_for("jobs"))

        cursor.execute(
            """
            SELECT comments.id, users.name,
                   comments.comment, comments.created_at
            FROM comments
            JOIN users ON comments.user_id = users.id
            WHERE comments.job_id = %s
            ORDER BY comments.created_at DESC
            """,
            (job_id,)
        )
        comments = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "job_detail.html",
        job=job,
        comments=comments
    )


@app.route("/job/<int:job_id>/comment", methods=["POST"])
def add_comment(job_id):
    if not is_logged_in():
        flash("Please login to comment.", "warning")
        return redirect(
            url_for(
                "login",
                next=url_for("job_detail", job_id=job_id)
            )
        )

    if is_admin():
        flash("Admin accounts cannot post public comments.", "warning")
        return redirect(url_for("job_detail", job_id=job_id))

    comment_text = request.form.get("comment", "").strip()

    if not comment_text or len(comment_text) > 3000:
        flash("Enter a comment of up to 3,000 characters.", "warning")
        return redirect(url_for("job_detail", job_id=job_id))

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT id FROM jobs WHERE id = %s", (job_id,))
        if not cursor.fetchone():
            flash("Job not found.", "danger")
            return redirect(url_for("jobs"))

        cursor.execute(
            """
            INSERT INTO comments (job_id, user_id, comment)
            VALUES (%s, %s, %s)
            """,
            (job_id, session["user_id"], comment_text)
        )
        connection.commit()

    except Exception:
        connection.rollback()
        app.logger.exception("Could not add job comment")
        flash("Could not add the comment. Please try again.", "danger")

    else:
        flash("Comment added successfully.", "success")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("job_detail", job_id=job_id))


# =========================================================
# REGISTRATION
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "job_seeker").strip().lower()
    phone = request.form.get("phone", "").strip()
    location = request.form.get("location", "").strip()

    if not name or not email or not password:
        flash("Name, email and password are required.", "danger")
        return render_template("register.html")

    if len(name) > 120 or len(email) > 254:
        flash("Name or email is too long.", "danger")
        return render_template("register.html")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        flash("Enter a valid email address.", "danger")
        return render_template("register.html")

    if len(password) < 8:
        flash("Password must contain at least 8 characters.", "danger")
        return render_template("register.html")

    if role not in {"job_seeker", "employer"}:
        role = "job_seeker"

    profile_photo = None

    try:
        profile_photo = save_profile_photo(request.files.get("profile_photo"))
    except ValueError as error:
        flash(str(error), "danger")
        return render_template("register.html")

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            "SELECT id FROM users WHERE LOWER(email) = LOWER(%s)",
            (email,)
        )

        if cursor.fetchone():
            if profile_photo:
                delete_profile_photo(profile_photo)
            flash("This email is already registered. Please login.", "warning")
            return redirect(url_for("login"))

        cursor.execute(
            """
            INSERT INTO users
                (name, email, password_hash, role, phone, location, profile_photo)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                name,
                email,
                generate_password_hash(password),
                role,
                phone or None,
                location or None,
                profile_photo
            )
        )

        connection.commit()

    except Exception:
        connection.rollback()
        if profile_photo:
            delete_profile_photo(profile_photo)
        app.logger.exception("Registration failed")
        flash("Registration could not be completed. Please try again.", "danger")
        return render_template("register.html")

    finally:
        cursor.close()
        connection.close()

    flash("Registration successful. Please login.", "success")
    return redirect(url_for("login"))


# =========================================================
# LOGIN / LOGOUT
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    next_page = safe_next_url(request.form.get("next", "").strip())

    if not email or not password:
        flash("Please enter your email and password.", "danger")
        return render_template("login.html", next=next_page or "")

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT id, name, email, password_hash, role, profile_photo
            FROM users
            WHERE LOWER(email) = LOWER(%s)
            """,
            (email,)
        )
        user = cursor.fetchone()

    finally:
        cursor.close()
        connection.close()

    if not user or not check_password_hash(user[3] or "", password):
        flash("Invalid email or password.", "danger")
        return render_template("login.html", next=next_page or "")

    session.clear()
    session["user_id"] = user[0]
    session["user_name"] = user[1]
    session["email"] = user[2]
    session["role"] = user[4]
    session["profile_photo"] = user[5]

    flash("Welcome back!", "success")

    if next_page:
        return redirect(next_page)

    if user[4] == "admin":
        return redirect(url_for("admin_dashboard"))

    if user[4] == "employer":
        return redirect(url_for("employer_portal"))

    return redirect(url_for("home"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# =========================================================
# USER DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():
    redirect_response = login_required_redirect(url_for("dashboard"))
    if redirect_response:
        return redirect_response

    return render_template("dashboard.html", user=get_current_user())

# =========================================================
# MY APPLICATIONS - LOGGED-IN USER
# =========================================================

@app.route("/my-applications")
def my_applications():
    redirect_response = login_required_redirect(
        url_for("my_applications")
    )
    if redirect_response:
        return redirect_response

    # Admin accounts cannot apply for jobs.
    if is_admin():
        flash("Admin accounts cannot apply for jobs.", "warning")
        return redirect(url_for("admin_dashboard"))

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                applications.id,
                applications.job_id,
                jobs.title,
                companies.name,
                applications.status,
                applications.created_at
            FROM applications
            JOIN jobs ON applications.job_id = jobs.id
            JOIN companies ON jobs.company_id = companies.id
            WHERE applications.user_id = %s
            ORDER BY applications.created_at DESC NULLS LAST
            """,
            (session["user_id"],)
        )
        applications = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "my_applications.html",
        applications=applications
    )

# =========================================================
# PROFILE VIEW / UPDATE
# =========================================================

@app.route("/profile", methods=["GET", "POST"])
def profile():
    redirect_response = login_required_redirect(url_for("profile"))
    if redirect_response:
        return redirect_response

    current_user = get_current_user()

    if not current_user:
        session.clear()
        flash("Please login again.", "warning")
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("profile.html", user=current_user)

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    location = request.form.get("location", "").strip()
    bio = request.form.get("bio", "").strip()
    remove_photo = request.form.get("remove_photo") == "1"

    if not name or not email:
        flash("Name and email are required.", "danger")
        return render_template("profile.html", user=current_user)

    if len(name) > 120 or len(email) > 254 or len(bio) > 5000:
        flash("One or more fields exceed the allowed length.", "danger")
        return render_template("profile.html", user=current_user)

    new_photo = None

    try:
        if request.files.get("profile_photo") and request.files["profile_photo"].filename:
            new_photo = save_profile_photo(request.files["profile_photo"])
    except ValueError as error:
        flash(str(error), "danger")
        return render_template("profile.html", user=current_user)

    connection = get_db_connection()
    cursor = connection.cursor()

    old_photo = current_user[8]

    try:
        cursor.execute(
            """
            SELECT id FROM users
            WHERE LOWER(email) = LOWER(%s) AND id <> %s
            """,
            (email, session["user_id"])
        )

        if cursor.fetchone():
            if new_photo:
                delete_profile_photo(new_photo)
            flash("That email address is already used by another account.", "danger")
            return render_template("profile.html", user=current_user)

        if new_photo:
            photo_to_store = new_photo
        elif remove_photo:
            photo_to_store = None
        else:
            photo_to_store = old_photo

        cursor.execute(
            """
            UPDATE users
            SET name = %s, email = %s, phone = %s, location = %s,
                bio = %s, profile_photo = %s
            WHERE id = %s
            """,
            (
                name, email, phone or None, location or None,
                bio or None, photo_to_store, session["user_id"]
            )
        )

        connection.commit()

    except Exception:
        connection.rollback()
        if new_photo:
            delete_profile_photo(new_photo)
        app.logger.exception("Profile update failed")
        flash("Profile could not be updated. Please try again.", "danger")
        return render_template("profile.html", user=current_user)

    finally:
        cursor.close()
        connection.close()

    if new_photo or remove_photo:
        delete_profile_photo(old_photo)

    session["user_name"] = name
    session["email"] = email
    session["profile_photo"] = photo_to_store

    flash("Your profile has been updated.", "success")
    return redirect(url_for("profile"))


# =========================================================
# EMPLOYER PORTAL
# =========================================================

@app.route("/employer")
def employer_portal():
    redirect_response = login_required_redirect(url_for("employer_portal"))
    if redirect_response:
        return redirect_response

    if session.get("role") not in {"employer", "admin"}:
        flash("Only employers and admins can access this page.", "danger")
        return redirect(url_for("home"))

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT jobs.id, jobs.title, companies.name,
                   jobs.location, jobs.job_type,
                   jobs.salary_min, jobs.salary_max, jobs.created_at
            FROM jobs
            JOIN companies ON jobs.company_id = companies.id
            ORDER BY jobs.created_at DESC NULLS LAST
            """
        )
        employer_jobs = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    # This template name is retained from your existing app.py.
    return render_template("employer.html", jobs=employer_jobs)


# =========================================================
# POST JOB
# =========================================================

@app.route("/post-job", methods=["GET", "POST"])
def post_job():
    redirect_response = login_required_redirect(url_for("post_job"))
    if redirect_response:
        return redirect_response

    if session.get("role") not in {"employer", "admin"}:
        flash("Only employers or admins can post jobs.", "danger")
        return redirect(url_for("home"))

    if request.method == "GET":
        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            cursor.execute("SELECT id, name FROM companies ORDER BY name")
            companies = cursor.fetchall()
        finally:
            cursor.close()
            connection.close()

        return render_template("post_job.html", companies=companies)

    title = request.form.get("title", "").strip()
    company_name = request.form.get("company_name", "").strip()
    location = request.form.get("location", "").strip()
    job_type = request.form.get("job_type", "").strip()
    description = request.form.get("description", "").strip()
    skills = request.form.get("skills", "").strip()
    experience = request.form.get("experience", "").strip()

    try:
        salary_min = Decimal(request.form["salary_min"]) if request.form.get("salary_min", "").strip() else None
        salary_max = Decimal(request.form["salary_max"]) if request.form.get("salary_max", "").strip() else None
        if (salary_min is not None and salary_min < 0) or (salary_max is not None and salary_max < 0):
            raise ValueError
        if salary_min is not None and salary_max is not None and salary_min > salary_max:
            raise ValueError
    except (InvalidOperation, ValueError):
        flash("Enter valid non-negative salaries; minimum cannot exceed maximum.", "danger")
        return redirect(url_for("post_job"))

    if not title or not company_name or not location or not job_type:
        flash("Title, company, location and job type are required.", "danger")
        return redirect(url_for("post_job"))

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        company_id = get_or_create_company(cursor, company_name)

        cursor.execute(
            """
            INSERT INTO jobs
                (company_id, title, description, location, job_type,
                 salary_min, salary_max, experience, skills)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                company_id, title, description, location, job_type,
                salary_min, salary_max, experience, skills
            )
        )

        connection.commit()

    except Exception:
        connection.rollback()
        app.logger.exception("Job creation failed")
        flash("The job could not be posted.", "danger")
        return redirect(url_for("post_job"))

    finally:
        cursor.close()
        connection.close()

    flash("Job posted successfully.", "success")
    return redirect(url_for("employer_portal"))


# =========================================================
# APPLY FOR JOB
# =========================================================

@app.route("/apply/<int:job_id>", methods=["GET", "POST"])
def apply(job_id):
    if not is_logged_in():
        flash("Please login to apply for a job.", "warning")
        return redirect(url_for("login", next=url_for("job_detail", job_id=job_id)))

    if is_admin():
        flash("Admin accounts cannot apply for jobs.", "warning")
        return redirect(url_for("job_detail", job_id=job_id))

    job = fetch_job(job_id)

    if not job:
        flash("Job not found.", "danger")
        return redirect(url_for("jobs"))

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT id FROM applications
            WHERE user_id = %s AND job_id = %s
            """,
            (session["user_id"], job_id)
        )
        existing_application = cursor.fetchone()

        if existing_application:
            flash("You have already applied for this job.", "warning")
            return redirect(url_for("my_applications"))

        if request.method == "GET":
            return render_template("apply.html", job=job)

        cover_letter = request.form.get("cover_letter", "").strip()

        cursor.execute(
            """
            INSERT INTO applications (user_id, job_id, cover_letter, status)
            VALUES (%s, %s, %s, %s)
            """,
            (session["user_id"], job_id, cover_letter, "Pending")
        )
        connection.commit()

        flash("Your application has been submitted successfully!", "success")
        return redirect(url_for("my_applications"))

    except Exception:
        connection.rollback()
        app.logger.exception("Job application failed")
        flash("Application failed. Please try again.", "danger")
        return redirect(url_for("job_detail", job_id=job_id))

    finally:
        cursor.close()
        connection.close()# =========================================================

# ADMIN DASHBOARD
# =========================================================

@app.route("/admin")
@app.route("/admin/dashboard")
def admin_dashboard():
    if not admin_required():
        return redirect(
            url_for("login", next=url_for("admin_dashboard"))
        )

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM jobs")
        job_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM applications")
        application_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM comments")
        comment_count = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM job_reports WHERE status = %s",
            ("Open",)
        )
        report_count = cursor.fetchone()[0]

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "admin_dashboard.html",
        user_count=user_count,
        job_count=job_count,
        application_count=application_count,
        comment_count=comment_count,
        report_count=report_count
    )


# =========================================================
# SUBMIT JOB REPORT / COMPLAINT
# =========================================================

@app.route("/job/<int:job_id>/report", methods=["GET", "POST"])
def report_job(job_id):

    if not is_logged_in():
        flash("Please login to submit a report.", "warning")
        return redirect(
            url_for(
                "login",
                next=url_for("report_job", job_id=job_id)
            )
        )

    job = fetch_job(job_id)

    if not job:
        flash("Job not found.", "danger")
        return redirect(url_for("jobs"))

    if request.method == "POST":
        reason = request.form.get("reason", "Other").strip()
        description = request.form.get("description", "").strip()

        if reason not in REPORT_REASONS:
            reason = "Other"

        if not description:
            flash(
                "Please describe your complaint before posting.",
                "warning"
            )
            return render_template("report_job.html", job=job)

        if len(description) > 5000:
            flash(
                "Complaint must be 5,000 characters or fewer.",
                "warning"
            )
            return render_template("report_job.html", job=job)

        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO job_reports
                    (job_id, user_id, reason, description, status)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    job_id,
                    session["user_id"],
                    reason,
                    description,
                    "Open"
                )
            )

            connection.commit()

        except Exception:
            connection.rollback()
            app.logger.exception("Job report submission failed")
            flash(
                "Report could not be submitted. Please try again.",
                "danger"
            )
            return render_template("report_job.html", job=job)

        finally:
            cursor.close()
            connection.close()

        flash("Your report has been posted successfully.", "success")
        return redirect(url_for("job_detail", job_id=job_id))

    return render_template("report_job.html", job=job)


# =========================================================
# ADMIN REPORTS
# =========================================================

@app.route("/admin/reports")
def admin_reports():
    if not admin_required():
        return redirect(url_for("login", next=url_for("admin_reports")))

    status = request.args.get("status", "").strip()
    allowed_statuses = {"Open", "Under Review", "Resolved", "Dismissed"}

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        if status in allowed_statuses:
            cursor.execute(
                """
                SELECT r.id, r.job_id, j.title, u.name, u.email,
                       r.reason, r.description, r.status,
                       r.resolution_note, r.created_at, r.updated_at
                FROM job_reports r
                JOIN jobs j ON r.job_id = j.id
                JOIN users u ON r.user_id = u.id
                WHERE r.status = %s
                ORDER BY r.created_at DESC
                """,
                (status,)
            )
        else:
            cursor.execute(
                """
                SELECT r.id, r.job_id, j.title, u.name, u.email,
                       r.reason, r.description, r.status,
                       r.resolution_note, r.created_at, r.updated_at
                FROM job_reports r
                JOIN jobs j ON r.job_id = j.id
                JOIN users u ON r.user_id = u.id
                ORDER BY r.created_at DESC
                """
            )

        reports = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "admin_reports.html",
        reports=reports,
        selected_status=status
    )


@app.route("/admin/reports/<int:report_id>/update", methods=["POST"])
def admin_update_report(report_id):
    if not admin_required():
        admin_denied()

    status = request.form.get("status", "").strip()
    resolution_note = request.form.get("resolution_note", "").strip()

    allowed_statuses = {"Open", "Under Review", "Resolved", "Dismissed"}

    if status not in allowed_statuses:
        flash("Invalid report status.", "danger")
        return redirect(url_for("admin_reports"))

    if len(resolution_note) > 5000:
        flash("Resolution note is too long.", "danger")
        return redirect(url_for("admin_reports"))

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            UPDATE job_reports
            SET status = %s, resolution_note = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
            """,
            (status, resolution_note or None, report_id)
        )
        connection.commit()

        if cursor.rowcount:
            flash("Report updated.", "success")
        else:
            flash("Report not found.", "warning")

    except Exception:
        connection.rollback()
        app.logger.exception("Report update failed")
        flash("Could not update the report.", "danger")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_reports"))


@app.route("/admin/reports/<int:report_id>/delete", methods=["POST"])
def admin_delete_report(report_id):
    if not admin_required():
        admin_denied()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("DELETE FROM job_reports WHERE id = %s", (report_id,))
        connection.commit()
        flash(
            "Report deleted." if cursor.rowcount else "Report not found.",
            "success" if cursor.rowcount else "warning"
        )

    except Exception:
        connection.rollback()
        app.logger.exception("Report deletion failed")
        flash("Could not delete the report.", "danger")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_reports"))


# =========================================================
# ADMIN USERS
# =========================================================

@app.route("/admin/users")
def admin_users():
    if not admin_required():
        admin_denied()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT id, name, email, role
            FROM users
            ORDER BY id DESC
            """
        )
        users = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template("admin_users.html", users=users)


@app.route("/admin/users/create", methods=["GET", "POST"])
def admin_create_user():
    if not admin_required():
        admin_denied()

    if request.method == "GET":
        return render_template("admin_user_form.html")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "job_seeker").strip().lower()

    if not name or not email or len(password) < 8:
        flash("Enter name, email and a password of at least 8 characters.", "danger")
        return render_template("admin_user_form.html")

    if role not in {"admin", "employer", "job_seeker", "user"}:
        flash("Invalid role.", "danger")
        return render_template("admin_user_form.html")

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT id FROM users WHERE LOWER(email) = %s", (email,))
        if cursor.fetchone():
            flash("Email already exists.", "danger")
            return render_template("admin_user_form.html")

        cursor.execute(
            """
            INSERT INTO users (name, email, password_hash, role)
            VALUES (%s, %s, %s, %s)
            """,
            (name, email, generate_password_hash(password), role)
        )
        connection.commit()
        flash("User created successfully.", "success")
        return redirect(url_for("admin_users"))

    except Exception:
        connection.rollback()
        app.logger.exception("Admin user creation failed")
        flash("Could not create the user.", "danger")
        return render_template("admin_user_form.html")

    finally:
        cursor.close()
        connection.close()


@app.route("/admin/users/edit/<int:user_id>", methods=["GET", "POST"])
def admin_edit_user(user_id):
    if not admin_required():
        admin_denied()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        if request.method == "GET":
            cursor.execute(
                "SELECT id, name, email, role FROM users WHERE id = %s",
                (user_id,)
            )
            user = cursor.fetchone()

            if not user:
                flash("User not found.", "danger")
                return redirect(url_for("admin_users"))

            return render_template("admin_user_form.html", user=user)

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "job_seeker").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or role not in {
            "admin", "employer", "job_seeker", "user"
        }:
            flash("Enter valid user details.", "danger")
            return redirect(url_for("admin_edit_user", user_id=user_id))

        cursor.execute(
            """
            SELECT id FROM users
            WHERE LOWER(email) = %s AND id <> %s
            """,
            (email, user_id)
        )

        if cursor.fetchone():
            flash("That email is already in use.", "danger")
            return redirect(url_for("admin_edit_user", user_id=user_id))

        if password:
            if len(password) < 8:
                flash("New password must contain at least 8 characters.", "danger")
                return redirect(url_for("admin_edit_user", user_id=user_id))

            cursor.execute(
                """
                UPDATE users SET name=%s, email=%s, role=%s, password_hash=%s
                WHERE id=%s
                """,
                (name, email, role, generate_password_hash(password), user_id)
            )
        else:
            cursor.execute(
                """
                UPDATE users SET name=%s, email=%s, role=%s
                WHERE id=%s
                """,
                (name, email, role, user_id)
            )

        connection.commit()
        flash("User updated successfully.", "success")
        return redirect(url_for("admin_users"))

    except Exception:
        connection.rollback()
        app.logger.exception("Admin user update failed")
        flash("Could not update the user.", "danger")
        return redirect(url_for("admin_users"))

    finally:
        cursor.close()
        connection.close()


@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    if not admin_required():
        admin_denied()

    if user_id == session.get("user_id"):
        flash("You cannot delete your own admin account.", "danger")
        return redirect(url_for("admin_users"))

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        connection.commit()
        flash(
            "User deleted." if cursor.rowcount else "User not found.",
            "success" if cursor.rowcount else "warning"
        )

    except Exception:
        connection.rollback()
        app.logger.exception("Admin user deletion failed")
        flash("Could not delete the user. Check linked records and database constraints.", "danger")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_users"))


# =========================================================
# ADMIN JOBS
# =========================================================

@app.route("/admin/jobs")
def admin_jobs():
    if not admin_required():
        admin_denied()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT jobs.id, jobs.title, companies.name, jobs.location,
                   jobs.job_type, jobs.salary_min, jobs.salary_max,
                   jobs.experience, jobs.skills, jobs.created_at
            FROM jobs
            JOIN companies ON jobs.company_id = companies.id
            ORDER BY jobs.created_at DESC NULLS LAST
            """
        )
        jobs_list = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template("admin_jobs.html", jobs=jobs_list)


@app.route("/admin/jobs/create", methods=["GET", "POST"])
def admin_create_job():
    if not admin_required():
        admin_denied()

    if request.method == "GET":
        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT id, name FROM companies ORDER BY name")
            companies = cursor.fetchall()
        finally:
            cursor.close()
            connection.close()

        return render_template("admin_job_form.html", companies=companies)

    title = request.form.get("title", "").strip()
    company_name = request.form.get("company_name", "").strip()
    location = request.form.get("location", "").strip()
    job_type = request.form.get("job_type", "").strip()
    description = request.form.get("description", "").strip()
    skills = request.form.get("skills", "").strip()
    experience = request.form.get("experience", "").strip()

    try:
        salary_min = Decimal(request.form["salary_min"]) if request.form.get("salary_min", "").strip() else None
        salary_max = Decimal(request.form["salary_max"]) if request.form.get("salary_max", "").strip() else None
        if (salary_min is not None and salary_min < 0) or (salary_max is not None and salary_max < 0):
            raise ValueError
        if salary_min is not None and salary_max is not None and salary_min > salary_max:
            raise ValueError
    except (InvalidOperation, ValueError):
        flash("Enter valid salary values.", "danger")
        return redirect(url_for("admin_create_job"))

    if not title or not company_name or not location or not job_type:
        flash("Title, company, location and job type are required.", "danger")
        return redirect(url_for("admin_create_job"))

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        company_id = get_or_create_company(cursor, company_name)
        cursor.execute(
            """
            INSERT INTO jobs
                (company_id, title, description, location, job_type,
                 salary_min, salary_max, experience, skills)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                company_id, title, description, location, job_type,
                salary_min, salary_max, experience, skills
            )
        )
        connection.commit()
        flash("Job created successfully.", "success")
        return redirect(url_for("admin_jobs"))

    except Exception:
        connection.rollback()
        app.logger.exception("Admin job creation failed")
        flash("Could not create the job.", "danger")
        return redirect(url_for("admin_jobs"))

    finally:
        cursor.close()
        connection.close()


@app.route("/admin/jobs/edit/<int:job_id>", methods=["GET", "POST"])
def admin_edit_job(job_id):
    if not admin_required():
        admin_denied()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        if request.method == "GET":
            cursor.execute(
                """
                SELECT jobs.id, jobs.title, companies.name, jobs.location,
                       jobs.job_type, jobs.salary_min, jobs.salary_max,
                       jobs.experience, jobs.skills, jobs.description
                FROM jobs JOIN companies ON jobs.company_id = companies.id
                WHERE jobs.id = %s
                """,
                (job_id,)
            )
            job = cursor.fetchone()

            cursor.execute("SELECT id, name FROM companies ORDER BY name")
            companies = cursor.fetchall()

            if not job:
                flash("Job not found.", "danger")
                return redirect(url_for("admin_jobs"))

            return render_template(
                "admin_job_form.html", job=job, companies=companies
            )

        title = request.form.get("title", "").strip()
        company_name = request.form.get("company_name", "").strip()
        location = request.form.get("location", "").strip()
        job_type = request.form.get("job_type", "").strip()
        description = request.form.get("description", "").strip()
        skills = request.form.get("skills", "").strip()
        experience = request.form.get("experience", "").strip()

        try:
            salary_min = Decimal(request.form["salary_min"]) if request.form.get("salary_min", "").strip() else None
            salary_max = Decimal(request.form["salary_max"]) if request.form.get("salary_max", "").strip() else None
            if (salary_min is not None and salary_min < 0) or (salary_max is not None and salary_max < 0):
                raise ValueError
            if salary_min is not None and salary_max is not None and salary_min > salary_max:
                raise ValueError
        except (InvalidOperation, ValueError):
            flash("Enter valid salary values.", "danger")
            return redirect(url_for("admin_edit_job", job_id=job_id))

        if not title or not company_name or not location or not job_type:
            flash("Title, company, location and job type are required.", "danger")
            return redirect(url_for("admin_edit_job", job_id=job_id))

        company_id = get_or_create_company(cursor, company_name)

        cursor.execute(
            """
            UPDATE jobs
            SET company_id=%s, title=%s, description=%s, location=%s,
                job_type=%s, salary_min=%s, salary_max=%s,
                experience=%s, skills=%s
            WHERE id=%s
            """,
            (
                company_id, title, description, location, job_type,
                salary_min, salary_max, experience, skills, job_id
            )
        )

        connection.commit()
        flash("Job updated successfully.", "success")
        return redirect(url_for("admin_jobs"))

    except Exception:
        connection.rollback()
        app.logger.exception("Admin job update failed")
        flash("Could not update the job.", "danger")
        return redirect(url_for("admin_jobs"))

    finally:
        cursor.close()
        connection.close()


@app.route("/admin/jobs/delete/<int:job_id>", methods=["POST"])
def admin_delete_job(job_id):
    if not admin_required():
        admin_denied()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        # Delete dependent records first, preserving FK consistency.
        cursor.execute("DELETE FROM comments WHERE job_id = %s", (job_id,))
        cursor.execute("DELETE FROM applications WHERE job_id = %s", (job_id,))
        cursor.execute("DELETE FROM job_reports WHERE job_id = %s", (job_id,))
        cursor.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
        connection.commit()
        flash("Job and its related records deleted.", "success")

    except Exception:
        connection.rollback()
        app.logger.exception("Admin job deletion failed")
        flash("Could not delete the job.", "danger")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_jobs"))


# =========================================================
# ADMIN APPLICATIONS
# =========================================================

@app.route("/admin/applications")
def admin_applications():
    if not admin_required():
        admin_denied()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT applications.id, users.name, users.email, jobs.title,
                   applications.cover_letter, applications.created_at
            FROM applications
            JOIN users ON applications.user_id = users.id
            JOIN jobs ON applications.job_id = jobs.id
            ORDER BY applications.created_at DESC NULLS LAST
            """
        )
        applications = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template("admin_applications.html", applications=applications)


@app.route("/admin/applications/delete/<int:application_id>", methods=["POST"])
def admin_delete_application(application_id):
    if not admin_required():
        admin_denied()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("DELETE FROM applications WHERE id = %s", (application_id,))
        connection.commit()
        flash("Application deleted.", "success")

    except Exception:
        connection.rollback()
        app.logger.exception("Application deletion failed")
        flash("Could not delete the application.", "danger")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_applications"))


# =========================================================
# ADMIN COMMENTS
# =========================================================

@app.route("/admin/comments")
def admin_comments():
    if not admin_required():
        admin_denied()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT comments.id, users.name, users.email, jobs.title,
                   comments.comment, comments.created_at
            FROM comments
            JOIN users ON comments.user_id = users.id
            JOIN jobs ON comments.job_id = jobs.id
            ORDER BY comments.created_at DESC
            """
        )
        comments = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template("admin_comments.html", comments=comments)


@app.route("/admin/comments/delete/<int:comment_id>", methods=["POST"])
def admin_delete_comment(comment_id):
    if not admin_required():
        admin_denied()

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("DELETE FROM comments WHERE id = %s", (comment_id,))
        connection.commit()
        flash("Comment deleted.", "success")

    except Exception:
        connection.rollback()
        app.logger.exception("Comment deletion failed")
        flash("Could not delete the comment.", "danger")

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("admin_comments"))


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(403)
def forbidden_error(error):
    return render_template(
        "base.html",
        error_message="You do not have permission to access this page."
    ), 403


@app.errorhandler(413)
def upload_too_large(error):
    flash("The uploaded file is too large.", "danger")
    return redirect(request.referrer or url_for("home"))


# =========================================================
# START APPLICATION
# =========================================================
if __name__ == "__main__":
    initialize_additive_schema()
    app.run(debug=True)