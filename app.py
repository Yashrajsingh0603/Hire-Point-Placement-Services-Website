from flask import Flask, render_template, request, redirect, url_for, session, flash
from database import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "hirehub-secret-key-2026"


# =========================================================
# ADMIN LOGIN PROTECTION
# =========================================================

def admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            return redirect(url_for("login"))

        if session.get("user_role") != "admin":
            return "Access Denied - Admins Only", 403

        return function(*args, **kwargs)

    return decorated_function


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]

    keyword = request.args.get("keyword", "").strip()
    location = request.args.get("location", "").strip()

    if keyword or location:

        cursor.execute("""
            SELECT
                jobs.title,
                companies.name,
                jobs.location,
                jobs.job_type,
                jobs.salary_min,
                jobs.salary_max,
                jobs.skills
            FROM jobs
            JOIN companies
                ON jobs.company_id = companies.id
            WHERE
                (
                    jobs.title ILIKE %s
                    OR jobs.description ILIKE %s
                    OR jobs.skills ILIKE %s
                    OR companies.name ILIKE %s
                )
                AND
                (
                    jobs.location ILIKE %s
                    OR %s = ''
                )
            ORDER BY jobs.created_at DESC
        """, (
            f"%{keyword}%",
            f"%{keyword}%",
            f"%{keyword}%",
            f"%{keyword}%",
            f"%{location}%",
            location
        ))

    else:

        cursor.execute("""
            SELECT
                jobs.title,
                companies.name,
                jobs.location,
                jobs.job_type,
                jobs.salary_min,
                jobs.salary_max,
                jobs.skills
            FROM jobs
            JOIN companies
                ON jobs.company_id = companies.id
            ORDER BY jobs.created_at DESC
        """)

    jobs = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "index.html",
        user_count=user_count,
        jobs=jobs
    )


# =========================================================
# JOBS PAGE
# =========================================================

@app.route("/jobs")
def jobs():

    connection = get_db_connection()
    cursor = connection.cursor()

    keyword = request.args.get("keyword", "").strip()
    location = request.args.get("location", "").strip()

    if keyword or location:

        cursor.execute("""
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
            JOIN companies
                ON jobs.company_id = companies.id
            WHERE
                (
                    jobs.title ILIKE %s
                    OR jobs.description ILIKE %s
                    OR jobs.skills ILIKE %s
                    OR companies.name ILIKE %s
                )
                AND
                (
                    jobs.location ILIKE %s
                    OR %s = ''
                )
            ORDER BY jobs.created_at DESC
        """, (
            f"%{keyword}%",
            f"%{keyword}%",
            f"%{keyword}%",
            f"%{keyword}%",
            f"%{location}%",
            location
        ))

    else:

        cursor.execute("""
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
            JOIN companies
                ON jobs.company_id = companies.id
            ORDER BY jobs.created_at DESC
        """)

    jobs_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "jobs.html",
        jobs=jobs_list,
        keyword=keyword,
        location=location
    )


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        role = request.form["role"]

        if role not in ["job_seeker", "employer"]:
            role = "job_seeker"

        password_hash = generate_password_hash(password)

        connection = get_db_connection()
        cursor = connection.cursor()

        try:

            cursor.execute("""
                INSERT INTO users
                (name, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
            """, (
                name,
                email,
                password_hash,
                role
            ))

            connection.commit()

        except Exception as error:

            connection.rollback()

            cursor.close()
            connection.close()

            return f"Registration failed: {error}"

        cursor.close()
        connection.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip()
        password = request.form["password"]

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
                name,
                email,
                password_hash,
                role
            FROM users
            WHERE email = %s
        """, (email,))

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user and check_password_hash(user[3], password):

            session["user_id"] = user[0]
            session["user_name"] = user[1]
            session["user_email"] = user[2]
            session["user_role"] = user[4]

            if user[4] == "admin":
                return redirect(url_for("admin_dashboard"))

            return redirect(url_for("home"))

        return "Invalid email or password"

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM jobs")
    total_jobs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM companies")
    total_companies = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM applications")
    total_applications = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_jobs=total_jobs,
        total_companies=total_companies,
        total_applications=total_applications
    )


# =========================================================
# ADMIN USERS
# =========================================================

@app.route("/admin/users")
@admin_required
def admin_users():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            email,
            role,
            created_at
        FROM users
        ORDER BY id DESC
    """)

    users = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_users.html",
        users=users
    )


# =========================================================
# CREATE USER
# =========================================================

@app.route("/admin/users/create", methods=["GET", "POST"])
@admin_required
def admin_create_user():

    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        role = request.form["role"]

        password_hash = generate_password_hash(password)

        connection = get_db_connection()
        cursor = connection.cursor()

        try:

            cursor.execute("""
                INSERT INTO users
                (name, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
            """, (
                name,
                email,
                password_hash,
                role
            ))

            connection.commit()

        except Exception as error:

            connection.rollback()

            cursor.close()
            connection.close()

            return f"Could not create user: {error}"

        cursor.close()
        connection.close()

        return redirect(url_for("admin_users"))

    return render_template(
        "admin_user_form.html",
        user=None
    )


# =========================================================
# EDIT USER
# =========================================================

@app.route("/admin/users/edit/<int:user_id>", methods=["GET", "POST"])
@admin_required
def admin_edit_user(user_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            email,
            role,
            created_at
        FROM users
        WHERE id = %s
    """, (user_id,))

    user = cursor.fetchone()

    if user is None:

        cursor.close()
        connection.close()

        return "User not found", 404

    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        role = request.form["role"]

        if password:

            password_hash = generate_password_hash(password)

            cursor.execute("""
                UPDATE users
                SET
                    name = %s,
                    email = %s,
                    password_hash = %s,
                    role = %s
                WHERE id = %s
            """, (
                name,
                email,
                password_hash,
                role,
                user_id
            ))

        else:

            cursor.execute("""
                UPDATE users
                SET
                    name = %s,
                    email = %s,
                    role = %s
                WHERE id = %s
            """, (
                name,
                email,
                role,
                user_id
            ))

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("admin_users"))

    cursor.close()
    connection.close()

    return render_template(
        "admin_user_form.html",
        user=user
    )


# =========================================================
# DELETE USER
# =========================================================

@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete_user(user_id):

    if session.get("user_id") == user_id:
        return "You cannot delete the currently logged-in admin.", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM users WHERE id = %s",
        (user_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("admin_users"))


# =========================================================
# POST JOB
# =========================================================

@app.route("/post-job", methods=["GET", "POST"])
def post_job():

    if "user_id" not in session:

        flash(
            "Please login first.",
            "warning"
        )

        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    # IMPORTANT:
    # Your companies table uses "name"
    cursor.execute("""
        SELECT
            id,
            name
        FROM companies
        ORDER BY name
    """)

    companies = cursor.fetchall()

    if request.method == "POST":

        company_id = request.form["company_id"]

        title = request.form["title"].strip()

        description = request.form["description"].strip()

        location = request.form["location"].strip()

        job_type = request.form["job_type"].strip()

        salary_min = request.form["salary_min"] or None

        salary_max = request.form["salary_max"] or None

        experience = request.form["experience"].strip()

        skills = request.form["skills"].strip()

        try:

            cursor.execute("""
                INSERT INTO jobs
                (
                    company_id,
                    title,
                    description,
                    location,
                    job_type,
                    salary_min,
                    salary_max,
                    experience,
                    skills
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
            """, (
                company_id,
                title,
                description,
                location,
                job_type,
                salary_min,
                salary_max,
                experience,
                skills
            ))

            connection.commit()

            cursor.close()
            connection.close()

            flash(
                "Job posted successfully!",
                "success"
            )

            return redirect(url_for("jobs"))

        except Exception as error:

            connection.rollback()

            cursor.close()
            connection.close()

            return f"Job posting failed: {error}"

    cursor.close()
    connection.close()

    return render_template(
        "post_job.html",
        companies=companies
    )
@app.route("/apply/<int:job_id>", methods=["GET", "POST"])
def apply_job(job_id):

    if "user_id" not in session:
        flash("Please login first to apply for a job.", "warning")
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    # Get job details
    cursor.execute("""
        SELECT
            jobs.id,
            jobs.title,
            companies.name,
            jobs.location,
            jobs.job_type
        FROM jobs
        JOIN companies ON jobs.company_id = companies.id
        WHERE jobs.id = %s
    """, (job_id,))

    job = cursor.fetchone()

    if job is None:
        cursor.close()
        connection.close()
        return "Job not found", 404

    # Submit application
    if request.method == "POST":

        cover_letter = request.form["cover_letter"].strip()

        if not cover_letter:
            cursor.close()
            connection.close()
            flash("Please write a cover letter.", "warning")
            return redirect(url_for("apply_job", job_id=job_id))

        # Check whether user already applied
        cursor.execute("""
            SELECT id
            FROM applications
            WHERE user_id = %s
            AND job_id = %s
        """, (session["user_id"], job_id))

        existing_application = cursor.fetchone()

        if existing_application:
            cursor.close()
            connection.close()
            flash("You have already applied for this job.", "warning")
            return redirect(url_for("jobs"))

        # Save application
        cursor.execute("""
            INSERT INTO applications
            (user_id, job_id, cover_letter)
            VALUES (%s, %s, %s)
        """, (
            session["user_id"],
            job_id,
            cover_letter
        ))

        connection.commit()

        cursor.close()
        connection.close()

        flash("Application submitted successfully!", "success")

        return redirect(url_for("jobs"))

    cursor.close()
    connection.close()

    return render_template(
        "apply.html",
        job=job
    )
# =========================================================
# ADMIN APPLICATIONS
# =========================================================

@app.route("/admin/applications")
@admin_required
def admin_applications():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            applications.id,
            users.name,
            users.email,
            jobs.title,
            companies.name,
            applications.cover_letter
        FROM applications
        JOIN users
            ON applications.user_id = users.id
        JOIN jobs
            ON applications.job_id = jobs.id
        JOIN companies
            ON jobs.company_id = companies.id
        ORDER BY applications.id DESC
    """)

    applications = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_applications.html",
        applications=applications
    )


# =========================================================
# ADMIN DELETE APPLICATION
# =========================================================

@app.route("/admin/applications/delete/<int:application_id>", methods=["POST"])
@admin_required
def admin_delete_application(application_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM applications
        WHERE id = %s
    """, (application_id,))

    connection.commit()

    cursor.close()
    connection.close()

    flash(
        "Application deleted successfully.",
        "success"
    )

    return redirect(url_for("admin_applications"))

# =========================================================
# ADMIN JOBS
# =========================================================

@app.route("/admin/jobs")
@admin_required
def admin_jobs():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            jobs.id,
            jobs.title,
            companies.name,
            jobs.location,
            jobs.job_type,
            jobs.salary_min,
            jobs.salary_max,
            jobs.skills,
            jobs.created_at
        FROM jobs
        JOIN companies
            ON jobs.company_id = companies.id
        ORDER BY jobs.id DESC
    """)

    jobs_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_jobs.html",
        jobs=jobs_list
    )


# =========================================================
# ADMIN CREATE JOB
# =========================================================

@app.route("/admin/jobs/create", methods=["GET", "POST"])
@admin_required
def admin_create_job():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            name
        FROM companies
        ORDER BY name
    """)

    companies = cursor.fetchall()

    if request.method == "POST":

        company_id = request.form["company_id"]

        title = request.form["title"].strip()

        description = request.form["description"].strip()

        location = request.form["location"].strip()

        job_type = request.form["job_type"].strip()

        salary_min = request.form["salary_min"] or None

        salary_max = request.form["salary_max"] or None

        experience = request.form["experience"].strip()

        skills = request.form["skills"].strip()

        cursor.execute("""
            INSERT INTO jobs
            (
                company_id,
                title,
                description,
                location,
                job_type,
                salary_min,
                salary_max,
                experience,
                skills
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
        """, (
            company_id,
            title,
            description,
            location,
            job_type,
            salary_min,
            salary_max,
            experience,
            skills
        ))

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("admin_jobs"))

    cursor.close()
    connection.close()

    return render_template(
        "admin_job_form.html",
        job=None,
        companies=companies
    )


# =========================================================
# ADMIN EDIT JOB
# =========================================================

@app.route("/admin/jobs/edit/<int:job_id>", methods=["GET", "POST"])
@admin_required
def admin_edit_job(job_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            company_id,
            title,
            description,
            location,
            job_type,
            salary_min,
            salary_max,
            experience,
            skills
        FROM jobs
        WHERE id = %s
    """, (job_id,))

    job = cursor.fetchone()

    if job is None:

        cursor.close()
        connection.close()

        return "Job not found", 404

    cursor.execute("""
        SELECT
            id,
            name
        FROM companies
        ORDER BY name
    """)

    companies = cursor.fetchall()

    if request.method == "POST":

        company_id = request.form["company_id"]

        title = request.form["title"].strip()

        description = request.form["description"].strip()

        location = request.form["location"].strip()

        job_type = request.form["job_type"].strip()

        salary_min = request.form["salary_min"] or None

        salary_max = request.form["salary_max"] or None

        experience = request.form["experience"].strip()

        skills = request.form["skills"].strip()

        cursor.execute("""
            UPDATE jobs
            SET
                company_id = %s,
                title = %s,
                description = %s,
                location = %s,
                job_type = %s,
                salary_min = %s,
                salary_max = %s,
                experience = %s,
                skills = %s
            WHERE id = %s
        """, (
            company_id,
            title,
            description,
            location,
            job_type,
            salary_min,
            salary_max,
            experience,
            skills,
            job_id
        ))

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(url_for("admin_jobs"))

    cursor.close()
    connection.close()

    return render_template(
        "admin_job_form.html",
        job=job,
        companies=companies
    )


# =========================================================
# ADMIN DELETE JOB
# =========================================================

@app.route("/admin/jobs/delete/<int:job_id>", methods=["POST"])
@admin_required
def admin_delete_job(job_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM jobs WHERE id = %s",
        (job_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("admin_jobs"))

# =========================================================
#                    USER COMMENTS
# =========================================================

@app.route("/comments", methods=["GET", "POST"])
def comments():

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        comment = request.form["comment"].strip()

        if not comment:
            cursor.close()
            connection.close()
            return "Comment cannot be empty."

        cursor.execute("""
            INSERT INTO comments (user_id, comment)
            VALUES (%s, %s)
        """, (
            session["user_id"],
            comment
        ))

        connection.commit()

    cursor.execute("""
        SELECT
            comments.id,
            users.name,
            comments.comment,
            comments.created_at
        FROM comments
        JOIN users
            ON comments.user_id = users.id
        ORDER BY comments.created_at DESC
    """)

    comments_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "comments.html",
        comments=comments_list
    )


# =========================================================
#                 ADMIN COMMENTS
# =========================================================

@app.route("/admin/comments")
@admin_required
def admin_comments():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            comments.id,
            users.name,
            users.email,
            comments.comment,
            comments.created_at
        FROM comments
        JOIN users
            ON comments.user_id = users.id
        ORDER BY comments.created_at DESC
    """)

    comments_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_comments.html",
        comments=comments_list
    )


# =========================================================
#                 DELETE COMMENT
# =========================================================

@app.route("/admin/comments/delete/<int:comment_id>", methods=["POST"])
@admin_required
def admin_delete_comment(comment_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM comments
        WHERE id = %s
    """, (comment_id,))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("admin_comments"))

# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)