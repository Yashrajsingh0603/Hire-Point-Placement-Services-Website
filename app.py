from flask import Flask, render_template, request, redirect, url_for, session, flash
from database import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "hirehub-secret-key-2026"


# =========================
# AUTH HELPERS
# =========================

def is_logged_in():
    return "user_id" in session


def is_admin():
    return session.get("role") == "admin"


def is_employer():
    return session.get("role") == "employer"


# =========================
# COMPANY HELPER
# =========================

def get_or_create_company(cursor, company_name):
    """
    Existing company mile to uski ID return karega.
    New company ho to database me create karke ID return karega.
    """

    company_name = company_name.strip()

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


# =========================
# HOME
# =========================

@app.route("/")
def home():

    connection = get_db_connection()
    cursor = connection.cursor()

    # ================= REAL COUNTS =================

    cursor.execute("SELECT COUNT(*) FROM users;")
    user_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM jobs;")
    job_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM companies;")
    company_count = cursor.fetchone()[0]

    # ================= JOB SEARCH =================

    keyword = request.args.get("keyword", "").strip()
    location = request.args.get("location", "").strip()

    keyword_search = "%" + keyword + "%"
    location_search = "%" + location + "%"

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
                %s = '%%'
                OR jobs.title ILIKE %s
                OR jobs.skills ILIKE %s
            )
            AND
            (
                %s = '%%'
                OR jobs.location ILIKE %s
            )
        ORDER BY jobs.created_at DESC
    """, (
        keyword_search,
        keyword_search,
        keyword_search,
        location_search,
        location_search
    ))

    jobs = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "index.html",
        jobs=jobs,
        keyword=keyword,
        location=location,
        user_count=user_count,
        job_count=job_count,
        company_count=company_count
    )


# =========================
# ALL JOBS
# =========================

@app.route("/jobs")
def jobs():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
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
        """
    )

    all_jobs = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "jobs.html",
        jobs=all_jobs
    )


# =========================
# JOB DETAILS
# =========================

@app.route("/job/<int:job_id>")
def job_detail(job_id):

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
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
        WHERE jobs.id = %s
        """,
        (job_id,)
    )

    job = cursor.fetchone()

    if not job:

        cursor.close()
        connection.close()

        flash(
            "Job not found.",
            "danger"
        )

        return redirect(
            url_for("home")
        )

    # ================= COMMENTS =================

    cursor.execute(
        """
        SELECT
            comments.id,
            users.name,
            comments.comment,
            comments.created_at
        FROM comments
        JOIN users
            ON comments.user_id = users.id
        WHERE comments.job_id = %s
        ORDER BY comments.created_at DESC
        """,
        (job_id,)
    )

    comments = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "job_detail.html",
        job=job,
        comments=comments
    )


# =========================
# REGISTER
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        role = request.form.get(
            "role",
            "job_seeker"
        ).strip().lower()

        if not name or not email or not password:

            flash(
                "Please fill all required fields.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        if role not in [
            "job_seeker",
            "employer"
        ]:

            role = "job_seeker"

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id
            FROM users
            WHERE LOWER(email) = LOWER(%s)
            """,
            (email,)
        )

        existing_user = cursor.fetchone()

        if existing_user:

            cursor.close()
            connection.close()

            flash(
                "Email already registered. Please login.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        password_hash = generate_password_hash(
            password
        )

        cursor.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                password_hash,
                role
            )
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                name,
                email,
                password_hash,
                role
            )
        )

        cursor.fetchone()

        connection.commit()

        cursor.close()
        connection.close()

        flash(
            "Registration successful. Please login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )

# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    # =========================
    # FIXED ADMIN LOGIN
    # =========================
    ADMIN_EMAIL = "admin@hirehub.com"
    ADMIN_PASSWORD = "Admin@123"

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Login ke baad kis page par jaana hai
        next_page = request.form.get("next", "").strip()

        if not email or not password:

            flash(
                "Please enter email and password.",
                "danger"
            )

            return render_template(
                "login.html",
                next=next_page
            )

        # =========================
        # ADMIN LOGIN
        # =========================

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:

            session.clear()

            session["user_id"] = 1
            session["user_name"] = "Administrator"
            session["email"] = ADMIN_EMAIL
            session["role"] = "admin"

            return redirect(
                url_for("admin_dashboard")
            )

        # =========================
        # NORMAL USER LOGIN
        # ANY EMAIL + ANY PASSWORD
        # =========================

        session.clear()

        # 1 is used instead of 0 because
        # 0 is considered False in Jinja.
        session["user_id"] = 1
        session["user_name"] = email.split("@")[0]
        session["email"] = email
        session["role"] = "user"

        # Login ke baad wahi page open karo
        if next_page and next_page.startswith("/"):
            return redirect(next_page)

        return redirect(
            url_for("home")
        )

    return render_template(
        "login.html"
    )
# =========================
# USER DASHBOARD
# =========================

@app.route("/dashboard")
def dashboard():

    if not is_logged_in():
        return redirect(
            url_for(
                "login",
                next=url_for("dashboard")
            )
        )

    return render_template(
        "dashboard.html"
    )
# =========================
# LOGOUT
# =========================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# =========================
# EMPLOYER PORTAL
# =========================

@app.route("/employer")
def employer_portal():

    if not is_logged_in():
        return redirect(
            url_for("login")
        )

    if session.get("role") not in [
        "employer",
        "admin"
    ]:

        flash(
            "Access denied.",
            "danger"
        )

        return redirect(
            url_for("home")
        )

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            jobs.id,
            jobs.title,
            companies.name,
            jobs.location,
            jobs.job_type,
            jobs.salary_min,
            jobs.salary_max,
            jobs.created_at
        FROM jobs
        JOIN companies
            ON jobs.company_id = companies.id
        ORDER BY jobs.created_at DESC
        """
    )

    employer_jobs = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "employer.html",
        jobs=employer_jobs
    )


# =========================
# POST JOB
# =========================

@app.route("/post-job", methods=["GET", "POST"])
def post_job():

    if not is_logged_in():
        return redirect(
            url_for("login")
        )

    if session.get("role") not in [
        "employer",
        "admin"
    ]:

        flash(
            "Only employers or admins can post jobs.",
            "danger"
        )

        return redirect(
            url_for("home")
        )

    connection = get_db_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        title = request.form.get(
            "title",
            ""
        ).strip()

        company_name = request.form.get(
            "company_name",
            ""
        ).strip()

        location = request.form.get(
            "location",
            ""
        ).strip()

        job_type = request.form.get(
            "job_type",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        skills = request.form.get(
            "skills",
            ""
        ).strip()

        experience = request.form.get(
            "experience",
            ""
        ).strip()

        salary_min = request.form.get(
            "salary_min",
            ""
        ).strip()

        salary_max = request.form.get(
            "salary_max",
            ""
        ).strip()

        if (
            not title
            or not company_name
            or not location
            or not job_type
        ):

            cursor.close()
            connection.close()

            flash(
                "Please fill all required job fields.",
                "danger"
            )

            return render_template(
                "post_job.html"
            )

        salary_min_value = None
        salary_max_value = None

        if salary_min:

            try:

                salary_min_value = int(
                    salary_min
                )

            except ValueError:

                cursor.close()
                connection.close()

                flash(
                    "Salary minimum must be a number.",
                    "danger"
                )

                return render_template(
                    "post_job.html"
                )

        if salary_max:

            try:

                salary_max_value = int(
                    salary_max
                )

            except ValueError:

                cursor.close()
                connection.close()

                flash(
                    "Salary maximum must be a number.",
                    "danger"
                )

                return render_template(
                    "post_job.html"
                )

        company_id = get_or_create_company(
            cursor,
            company_name
        )

        cursor.execute(
            """
            INSERT INTO jobs (
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
            VALUES (
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
            """,
            (
                company_id,
                title,
                description,
                location,
                job_type,
                salary_min_value,
                salary_max_value,
                experience,
                skills
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        flash(
            "Job posted successfully.",
            "success"
        )

        return redirect(
            url_for("employer_portal")
        )

    cursor.execute(
        """
        SELECT id, name
        FROM companies
        ORDER BY name
        """
    )

    companies = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "post_job.html",
        companies=companies
    )


# =========================
# APPLY FOR JOB
# =========================

@app.route(
    "/apply/<int:job_id>",
    methods=["GET", "POST"]
)
def apply(job_id):

    if not is_logged_in():

        flash(
            "Please login to apply for a job.",
            "warning"
        )

        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":

        flash(
            "Admin accounts cannot apply for jobs.",
            "warning"
        )

        return redirect(
            url_for(
                "job_detail",
                job_id=job_id
            )
        )

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, title
        FROM jobs
        WHERE id = %s
        """,
        (job_id,)
    )

    job = cursor.fetchone()

    if not job:

        cursor.close()
        connection.close()

        flash(
            "Job not found.",
            "danger"
        )

        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        cover_letter = request.form.get(
            "cover_letter",
            ""
        ).strip()

        cursor.execute(
            """
            SELECT id
            FROM applications
            WHERE user_id = %s
            AND job_id = %s
            """,
            (
                session["user_id"],
                job_id
            )
        )

        existing_application = cursor.fetchone()

        if existing_application:

            cursor.close()
            connection.close()

            flash(
                "You have already applied for this job.",
                "warning"
            )

            return redirect(
                url_for(
                    "job_detail",
                    job_id=job_id
                )
            )

        cursor.execute(
            """
            INSERT INTO applications
            (
                user_id,
                job_id,
                cover_letter
            )
            VALUES (%s, %s, %s)
            """,
            (
                session["user_id"],
                job_id,
                cover_letter
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        flash(
            "Application submitted successfully.",
            "success"
        )

        return redirect(
            url_for(
                "job_detail",
                job_id=job_id
            )
        )

    cursor.close()
    connection.close()

    return render_template(
        "apply.html",
        job=job
    )


# =========================
# ADD COMMENT
# =========================


@app.route(
    "/job/<int:job_id>/comment",
    methods=["POST"]
)
def add_comment(job_id):

    # User must be logged in
    if not is_logged_in():

        flash(
            "Please login to comment.",
            "warning"
        )

        # Login ke baad isi job par wapas aayega
        return redirect(
            url_for(
                "login",
                next=url_for(
                    "job_detail",
                    job_id=job_id
                )
            )
        )

    comment_text = request.form.get(
        "comment",
        ""
    ).strip()

    if not comment_text:

        flash(
            "Please write a comment.",
            "warning"
        )

        return redirect(
            url_for(
                "job_detail",
                job_id=job_id
            )
        )

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO comments
        (job_id, user_id, comment)
        VALUES (%s, %s, %s)
        """,
        (
            job_id,
            session.get("user_id"),
            comment_text
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    flash(
        "Comment added successfully!",
        "success"
    )
    return redirect(
        url_for(
            "job_detail",
            job_id=job_id
        )
    )


# =========================
# ADMIN PROTECTION
# =========================

def admin_required():

    if not is_logged_in():
        return False

    return session.get("role") == "admin"


# =========================
# ADMIN DASHBOARD
# =========================

@app.route("/admin")
@app.route("/admin/dashboard")
def admin_dashboard():

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM users"
    )

    user_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM jobs"
    )

    job_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM applications"
    )

    application_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM comments"
    )

    comment_count = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    return render_template(
        "admin_dashboard.html",
        user_count=user_count,
        job_count=job_count,
        application_count=application_count,
        comment_count=comment_count
    )


# =========================
# ADMIN USERS
# =========================

@app.route("/admin/users")
def admin_users():

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, name, email, role
        FROM users
        ORDER BY id DESC
        """
    )

    users = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_users.html",
        users=users
    )


@app.route(
    "/admin/users/create",
    methods=["GET", "POST"]
)
def admin_create_user():

    if not admin_required():
        return "Access Denied: Admin only.", 403

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        role = request.form.get(
            "role",
            "job_seeker"
        ).strip().lower()

        if not name or not email or not password:

            flash(
                "Please fill all fields.",
                "danger"
            )

            return render_template(
                "admin_user_form.html"
            )

        if role not in [
            "admin",
            "employer",
            "job_seeker",
            "user"
        ]:

            role = "job_seeker"

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id
            FROM users
            WHERE LOWER(email) = LOWER(%s)
            """,
            (email,)
        )

        existing = cursor.fetchone()

        if existing:

            cursor.close()
            connection.close()

            flash(
                "Email already exists.",
                "danger"
            )

            return render_template(
                "admin_user_form.html"
            )

        password_hash = generate_password_hash(
            password
        )

        cursor.execute(
            """
            INSERT INTO users
            (
                name,
                email,
                password_hash,
                role
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                name,
                email,
                password_hash,
                role
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        flash(
            "User created successfully.",
            "success"
        )

        return redirect(
            url_for("admin_users")
        )

    return render_template(
        "admin_user_form.html"
    )


@app.route(
    "/admin/users/edit/<int:user_id>",
    methods=["GET", "POST"]
)
def admin_edit_user(user_id):

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        role = request.form.get(
            "role",
            "job_seeker"
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if role not in [
            "admin",
            "employer",
            "job_seeker",
            "user"
        ]:

            role = "job_seeker"

        if password:

            password_hash = generate_password_hash(
                password
            )

            cursor.execute(
                """
                UPDATE users
                SET
                    name = %s,
                    email = %s,
                    password_hash = %s,
                    role = %s
                WHERE id = %s
                """,
                (
                    name,
                    email,
                    password_hash,
                    role,
                    user_id
                )
            )

        else:

            cursor.execute(
                """
                UPDATE users
                SET
                    name = %s,
                    email = %s,
                    role = %s
                WHERE id = %s
                """,
                (
                    name,
                    email,
                    role,
                    user_id
                )
            )

        connection.commit()

        cursor.close()
        connection.close()

        flash(
            "User updated successfully.",
            "success"
        )

        return redirect(
            url_for("admin_users")
        )

    cursor.execute(
        """
        SELECT id, name, email, role
        FROM users
        WHERE id = %s
        """,
        (user_id,)
    )

    user = cursor.fetchone()

    cursor.close()
    connection.close()

    if not user:

        flash(
            "User not found.",
            "danger"
        )

        return redirect(
            url_for("admin_users")
        )

    return render_template(
        "admin_user_form.html",
        user=user
    )


@app.route(
    "/admin/users/delete/<int:user_id>",
    methods=["POST", "GET"]
)
def admin_delete_user(user_id):

    if not admin_required():
        return "Access Denied: Admin only.", 403

    if user_id == session.get("user_id"):

        flash(
            "You cannot delete your own admin account.",
            "danger"
        )

        return redirect(
            url_for("admin_users")
        )

    connection = get_db_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            DELETE FROM comments
            WHERE user_id = %s
            """,
            (user_id,)
        )

        cursor.execute(
            """
            DELETE FROM applications
            WHERE user_id = %s
            """,
            (user_id,)
        )

        cursor.execute(
            """
            DELETE FROM users
            WHERE id = %s
            """,
            (user_id,)
        )

        connection.commit()

        flash(
            "User deleted successfully.",
            "success"
        )

    except Exception as error:

        connection.rollback()

        flash(
            "Could not delete user: " + str(error),
            "danger"
        )

    cursor.close()
    connection.close()

    return redirect(
        url_for("admin_users")
    )


# =========================
# ADMIN JOBS
# =========================

@app.route("/admin/jobs")
def admin_jobs():

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            jobs.id,
            jobs.title,
            companies.name,
            jobs.location,
            jobs.job_type,
            jobs.salary_min,
            jobs.salary_max,
            jobs.experience,
            jobs.skills,
            jobs.created_at
        FROM jobs
        JOIN companies
            ON jobs.company_id = companies.id
        ORDER BY jobs.created_at DESC
        """
    )

    jobs_list = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_jobs.html",
        jobs=jobs_list
    )


# =========================
# ADMIN CREATE JOB
# =========================

@app.route(
    "/admin/jobs/create",
    methods=["GET", "POST"]
)
def admin_create_job():

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        title = request.form.get(
            "title",
            ""
        ).strip()

        company_name = request.form.get(
            "company_name",
            ""
        ).strip()

        location = request.form.get(
            "location",
            ""
        ).strip()

        job_type = request.form.get(
            "job_type",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        skills = request.form.get(
            "skills",
            ""
        ).strip()

        experience = request.form.get(
            "experience",
            ""
        ).strip()

        salary_min = request.form.get(
            "salary_min",
            ""
        ).strip()

        salary_max = request.form.get(
            "salary_max",
            ""
        ).strip()

        if (
            not title
            or not company_name
            or not location
            or not job_type
        ):

            cursor.close()
            connection.close()

            flash(
                "Please fill all required fields.",
                "danger"
            )

            return render_template(
                "admin_job_form.html"
            )

        salary_min_value = None
        salary_max_value = None

        if salary_min:

            try:

                salary_min_value = int(
                    salary_min
                )

            except ValueError:

                cursor.close()
                connection.close()

                flash(
                    "Minimum salary must be a number.",
                    "danger"
                )

                return render_template(
                    "admin_job_form.html"
                )

        if salary_max:

            try:

                salary_max_value = int(
                    salary_max
                )

            except ValueError:

                cursor.close()
                connection.close()

                flash(
                    "Maximum salary must be a number.",
                    "danger"
                )

                return render_template(
                    "admin_job_form.html"
                )

        company_id = get_or_create_company(
            cursor,
            company_name
        )

        cursor.execute(
            """
            INSERT INTO jobs (
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
            VALUES (
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
            """,
            (
                company_id,
                title,
                description,
                location,
                job_type,
                salary_min_value,
                salary_max_value,
                experience,
                skills
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        flash(
            "Job created successfully.",
            "success"
        )

        return redirect(
            url_for("admin_jobs")
        )

    cursor.execute(
        """
        SELECT id, name
        FROM companies
        ORDER BY name
        """
    )

    companies = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_job_form.html",
        companies=companies
    )


# =========================
# ADMIN EDIT JOB
# =========================

@app.route(
    "/admin/jobs/edit/<int:job_id>",
    methods=["GET", "POST"]
)
def admin_edit_job(job_id):

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        title = request.form.get(
            "title",
            ""
        ).strip()

        company_name = request.form.get(
            "company_name",
            ""
        ).strip()

        location = request.form.get(
            "location",
            ""
        ).strip()

        job_type = request.form.get(
            "job_type",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        skills = request.form.get(
            "skills",
            ""
        ).strip()

        experience = request.form.get(
            "experience",
            ""
        ).strip()

        salary_min = request.form.get(
            "salary_min",
            ""
        ).strip()

        salary_max = request.form.get(
            "salary_max",
            ""
        ).strip()

        if (
            not title
            or not company_name
            or not location
            or not job_type
        ):

            cursor.close()
            connection.close()

            flash(
                "Please fill all required fields.",
                "danger"
            )

            return redirect(
                url_for(
                    "admin_edit_job",
                    job_id=job_id
                )
            )

        salary_min_value = None
        salary_max_value = None

        if salary_min:

            try:

                salary_min_value = int(
                    salary_min
                )

            except ValueError:

                cursor.close()
                connection.close()

                flash(
                    "Minimum salary must be a number.",
                    "danger"
                )

                return redirect(
                    url_for(
                        "admin_edit_job",
                        job_id=job_id
                    )
                )

        if salary_max:

            try:

                salary_max_value = int(
                    salary_max
                )

            except ValueError:

                cursor.close()
                connection.close()

                flash(
                    "Maximum salary must be a number.",
                    "danger"
                )

                return redirect(
                    url_for(
                        "admin_edit_job",
                        job_id=job_id
                    )
                )

        company_id = get_or_create_company(
            cursor,
            company_name
        )

        cursor.execute(
            """
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
            """,
            (
                company_id,
                title,
                description,
                location,
                job_type,
                salary_min_value,
                salary_max_value,
                experience,
                skills,
                job_id
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        flash(
            "Job updated successfully.",
            "success"
        )

        return redirect(
            url_for("admin_jobs")
        )

    cursor.execute(
        """
        SELECT
            jobs.id,
            jobs.title,
            companies.name,
            jobs.location,
            jobs.job_type,
            jobs.salary_min,
            jobs.salary_max,
            jobs.experience,
            jobs.skills,
            jobs.description
        FROM jobs
        JOIN companies
            ON jobs.company_id = companies.id
        WHERE jobs.id = %s
        """,
        (job_id,)
    )

    job = cursor.fetchone()

    cursor.execute(
        """
        SELECT id, name
        FROM companies
        ORDER BY name
        """
    )

    companies = cursor.fetchall()

    cursor.close()
    connection.close()

    if not job:

        flash(
            "Job not found.",
            "danger"
        )

        return redirect(
            url_for("admin_jobs")
        )

    return render_template(
        "admin_job_form.html",
        job=job,
        companies=companies
    )


# =========================
# ADMIN DELETE JOB
# =========================

@app.route(
    "/admin/jobs/delete/<int:job_id>",
    methods=["POST", "GET"]
)
def admin_delete_job(job_id):

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            DELETE FROM comments
            WHERE job_id = %s
            """,
            (job_id,)
        )

        cursor.execute(
            """
            DELETE FROM applications
            WHERE job_id = %s
            """,
            (job_id,)
        )

        cursor.execute(
            """
            DELETE FROM jobs
            WHERE id = %s
            """,
            (job_id,)
        )

        connection.commit()

        flash(
            "Job deleted successfully.",
            "success"
        )

    except Exception as error:

        connection.rollback()

        flash(
            "Could not delete job: " + str(error),
            "danger"
        )

    cursor.close()
    connection.close()

    return redirect(
        url_for("admin_jobs")
    )


# =========================
# ADMIN APPLICATIONS
# =========================

@app.route("/admin/applications")
def admin_applications():

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            applications.id,
            users.name,
            users.email,
            jobs.title,
            applications.cover_letter,
            applications.created_at
        FROM applications
        JOIN users
            ON applications.user_id = users.id
        JOIN jobs
            ON applications.job_id = jobs.id
        ORDER BY applications.created_at DESC
        """
    )

    applications = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_applications.html",
        applications=applications
    )


@app.route(
    "/admin/applications/delete/<int:application_id>",
    methods=["POST", "GET"]
)
def admin_delete_application(application_id):

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM applications
        WHERE id = %s
        """,
        (application_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    flash(
        "Application deleted successfully.",
        "success"
    )

    return redirect(
        url_for("admin_applications")
    )


# =========================
# ADMIN COMMENTS
# =========================

@app.route("/admin/comments")
def admin_comments():

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            comments.id,
            users.name,
            users.email,
            jobs.title,
            comments.comment,
            comments.created_at
        FROM comments
        JOIN users
            ON comments.user_id = users.id
        JOIN jobs
            ON comments.job_id = jobs.id
        ORDER BY comments.created_at DESC
        """
    )

    comments = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin_comments.html",
        comments=comments
    )


@app.route(
    "/admin/comments/delete/<int:comment_id>",
    methods=["POST", "GET"]
)
def admin_delete_comment(comment_id):

    if not admin_required():
        return "Access Denied: Admin only.", 403

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM comments
        WHERE id = %s
        """,
        (comment_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    flash(
        "Comment deleted successfully.",
        "success"
    )

    return redirect(
        url_for("admin_comments")
    )


# =========================
# RUN APPLICATION
# =========================

if __name__ == "__main__":
    app.run(debug=True)