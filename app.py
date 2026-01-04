# Flask core
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    session,
    send_file,
)

# Database & Models
from models import (
    db,
    User,
    Subject,
    Chapter,
    Quiz,
    Question,
    Score,
    UserAnswer,
    Feedback,
)

# Authentication
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)

# Security
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Migrations
from flask_migrate import Migrate

# Email
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

# File & Export Utilities
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import openpyxl
import csv
import io

# Standard Library
from datetime import datetime
import os
import random
from sqlalchemy import func


app = Flask(__name__)
# Mail configuration (using Gmail as example)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "your_email@gmail.com"  # Replace with your email
app.config["MAIL_PASSWORD"] = (
    "your_app_password"  # Use App Password, not your Gmail login
)
app.config["MAIL_DEFAULT_SENDER"] = "your_email@gmail.com"

mail = Mail(app)
app.config["SECRET_KEY"] = "quizsecret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///quiz.db"
db.init_app(app)

migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# For password reset tokens
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ✅ Create admin when DB is fresh
with app.app_context():
    db.create_all()
    if not User.query.filter_by(role="admin").first():
        admin = User(
            email="admin@gmail.com",
            password=generate_password_hash("admin123"),
            full_name="Quiz Master",
            role="admin",
        )
        db.session.add(admin)
        db.session.commit()


@app.route("/")
def welcome():
    return render_template("welcome.html")


# ---------------- AUTH ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # 🔹 Find user
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            # ✅ Login user
            login_user(user)

            # ✅ Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()

            flash(f"Welcome back, {user.full_name}!", "success")

            # ✅ Redirect with animation-ready route
            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("user_dashboard"))

        # ❌ Invalid credentials
        flash("Invalid email or password", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        password = request.form.get("password")
        qualification = request.form.get("qualification")
        dob = request.form.get("dob")

        # 🔒 Check if any field is missing
        if not full_name or not email or not password or not qualification or not dob:
            flash("All fields are required!", "error")
            return redirect(url_for("register"))

        # ❌ Check if email already exists
        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "warning")
            return redirect(url_for("register"))

        # 🔐 Hash password
        hashed_pw = generate_password_hash(password)

        # ✅ Create and store new user
        user = User(
            email=email,
            password=hashed_pw,
            full_name=full_name,
            qualification=qualification,
            dob=dob,
            role="user",
        )
        db.session.add(user)
        db.session.commit()

        flash("Registered successfully, please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect(url_for("welcome"))


# ---------------- BULK UPLOAD QUESTIONS ----------------
import io
import docx2txt
import PyPDF2
from werkzeug.utils import secure_filename
from flask import request, redirect, url_for, flash, render_template
from flask_login import login_required, current_user
from models import db, Quiz, Question


@app.route("/admin/upload_questions", methods=["GET", "POST"])
@login_required
def admin_upload_questions():
    # Restrict access to admins
    if current_user.role != "admin":
        flash("⛔ Access denied. Admins only.", "danger")
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":
        file = request.files.get("file")
        quiz_id = request.form.get("quiz_id")

        if not file or not quiz_id:
            flash("⚠️ Please select a file and a quiz.", "warning")
            return redirect(url_for("admin_upload_questions"))

        quiz = Quiz.query.get(quiz_id)
        if not quiz:
            flash("❌ Invalid quiz selected.", "danger")
            return redirect(url_for("admin_upload_questions"))

        filename = secure_filename(file.filename.lower())
        added = 0

        try:
            # -------------------------
            # Handle DOCX Upload
            # -------------------------
            if filename.endswith(".docx"):
                text = docx2txt.process(file)
                lines = text.split("\n")

                for line in lines:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) < 6:
                        continue
                    q = Question(
                        question_statement=parts[0],
                        option1=parts[1],
                        option2=parts[2],
                        option3=parts[3],
                        option4=parts[4],
                        correct_option=int(parts[5]),
                        quiz_id=quiz.id,
                    )
                    db.session.add(q)
                    added += 1

            # -------------------------
            # Handle PDF Upload
            # -------------------------
            elif filename.endswith(".pdf"):
                reader = PyPDF2.PdfReader(file)
                text = ""
                for page in reader.pages:
                    text += page.extract_text() + "\n"

                lines = text.split("\n")
                for line in lines:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) < 6:
                        continue
                    q = Question(
                        question_statement=parts[0],
                        option1=parts[1],
                        option2=parts[2],
                        option3=parts[3],
                        option4=parts[4],
                        correct_option=int(parts[5]),
                        quiz_id=quiz.id,
                    )
                    db.session.add(q)
                    added += 1

            else:
                flash("❌ Unsupported file type. Please upload PDF or DOCX.", "danger")
                return redirect(url_for("admin_upload_questions"))

            db.session.commit()
            flash(
                f"✅ {added} questions uploaded successfully to quiz '{quiz.name}'!",
                "success",
            )
            return redirect(url_for("manage_questions", quiz_id=quiz.id))

        except Exception as e:
            db.session.rollback()
            flash(f"❌ Error while uploading: {e}", "danger")
            return redirect(url_for("admin_upload_questions"))

    # GET request → show upload page
    quizzes = Quiz.query.all()
    return render_template("upload_questions.html", quizzes=quizzes)


# ---------------- USER BLOCK / UNBLOCK ----------------
# -------------------------#
# Block a User (Admin Only)
# -------------------------
@app.route("/admin/block_user/<int:user_id>")
@login_required
def admin_block_user(user_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    user = User.query.get_or_404(user_id)
    if user.role == "admin":
        flash("⚠️ You cannot block another admin.", "warning")
        return redirect(url_for("admin_users"))

    user.is_active = False  # Mark as inactive/blocked
    db.session.commit()
    flash(f"🚫 User {user.full_name} has been blocked.", "danger")
    return redirect(url_for("admin_users"))


# -------------------------
# Unblock a User (Admin Only)
# -------------------------
@app.route("/admin/unblock_user/<int:user_id>")
@login_required
def admin_unblock_user(user_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    user = User.query.get_or_404(user_id)
    user.is_active = True  # Mark as active again
    db.session.commit()
    flash(f"✅ User {user.full_name} has been unblocked.", "success")
    return redirect(url_for("admin_users"))


# -------------------------
# View All Blocked Users
# -------------------------
@app.route("/admin/unblock_users")
@login_required
def admin_unblock_users():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    # Fetch only blocked users
    users = User.query.filter_by(is_active=False).all()
    return render_template("admin_unblock_users.html", users=users)


# ---------------- PASSWORD RESET ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with this email.", "danger")
            return redirect(url_for("forgot_password"))

        token = serializer.dumps(email, salt="password-reset-salt")
        reset_url = url_for("reset_password", token=token, _external=True)
        # ✅ Send email instead of flash
        try:
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"""Hello {user.full_name},

To reset your password, click the link below:
{reset_url}

If you did not request a password reset, please ignore this email.
"""
            mail.send(msg)
            flash("✅ A password reset link has been sent to your email.", "info")
        except Exception as e:
            flash("❌ Failed to send email. Please try again later.", "danger")
            print("Email Error:", e)

        # In production → send email, here → show the link
        flash(f"Password reset link: {reset_url}", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except SignatureExpired:
        flash("The password reset link has expired.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Invalid password reset link.", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first_or_404()

    if request.method == "POST":
        new_password = request.form.get("password")
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Password reset successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


# ---------------- DASHBOARDS ----------------
@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    # ✅ Count total users and admins
    total_admins = User.query.filter_by(role="admin").count()
    total_users = User.query.filter_by(role="user").count()

    # ✅ Count total subjects
    total_subjects = Subject.query.count()

    # ✅ Count total quizzes
    total_quizzes = Quiz.query.count()
    published_quizzes = Quiz.query.filter_by(is_published=True).count()
    unpublished_quizzes = total_quizzes - published_quizzes

    # (Optional) keep for graphs
    subjects = Subject.query.all()
    subject_names = [s.name for s in subjects]
    quiz_counts = [sum(len(c.quizzes) for c in s.chapters) for s in subjects]

    # ===============================
    # QUIZ STATUS COUNTS (Pie Chart)
    # ===============================
    completed = Score.query.filter_by(status="Completed").count()
    pending = Score.query.filter_by(status="Pending").count()
    in_progress = Score.query.filter_by(status="In Progress").count()

    # ===============================
    # QUIZZES PER SUBJECT (Bar Chart)
    # ===============================
    quizzes_per_subject = (
        db.session.query(Subject.name, func.count(Quiz.id))
        .join(Chapter, Chapter.subject_id == Subject.id)
        .join(Quiz, Quiz.chapter_id == Chapter.id)
        .group_by(Subject.name)
        .all()
    )

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,  # ✅ matches your HTML
        total_subjects=total_subjects,  # ✅ matches your HTML
        total_quizzes=total_quizzes,
        total_admins=total_admins,  # optional extra
        subject_names=subject_names,
        quiz_counts=quiz_counts,
        published_quizzes=published_quizzes,
        unpublished_quizzes=unpublished_quizzes,
        quizzes_per_subject=quizzes_per_subject,
        completed=completed,
        pending=pending,
        in_progress=in_progress,
    )


# ---------------- ADMIN PROFILE ----------------
# configure upload folder
UPLOAD_FOLDER = os.path.join(os.getcwd(), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # limit: 2MB

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/admin/profile", methods=["GET", "POST"])
@login_required
def admin_profile():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":
        # ---------------- PROFILE UPDATE ----------------
        if "update_profile" in request.form:
            current_user.full_name = request.form.get("full_name", "").strip()
            current_user.email = request.form.get("email", "").strip()
            current_user.qualification = request.form.get("qualification", "").strip()
            current_user.dob = request.form.get("dob", "").strip()

            # ✅ Handle profile picture upload
            if "profile_picture" in request.files:
                file = request.files["profile_picture"]
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    file.save(filepath)

                    # update in db
                    current_user.profile_picture = filename

            db.session.commit()
            flash("✅ Profile updated successfully!", "success")
            return redirect(url_for("admin_profile"))

        # ---------------- PASSWORD CHANGE ----------------
        if "change_password" in request.form:
            old_password = request.form.get("old_password")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")

            if not check_password_hash(current_user.password, old_password):
                flash("❌ Old password is incorrect.", "danger")
                return redirect(url_for("admin_profile"))

            if new_password != confirm_password:
                flash("⚠️ New passwords do not match.", "warning")
                return redirect(url_for("admin_profile"))

            current_user.password = generate_password_hash(new_password)
            db.session.commit()
            flash("✅ Password changed successfully!", "success")
            return redirect(url_for("admin_profile"))

    return render_template("admin_profile.html")


@app.route("/user")
@login_required
def user_dashboard():
    if current_user.role != "user":
        return redirect(url_for("admin_dashboard"))

    # Scores by user
    scores = Score.query.filter_by(user_id=current_user.id).all()
    attempted_quiz_ids = {s.quiz_id for s in scores}

    # All published quizzes
    all_quizzes = Quiz.query.filter_by(is_published=True).all()

    completed = [q for q in all_quizzes if q.id in attempted_quiz_ids]
    pending = [q for q in all_quizzes if q.id not in attempted_quiz_ids]

    # In-progress (quiz started but not finished → custom logic)
    in_progress = [s.quiz for s in scores if s.total_scored == 0]

    # Prepare labels & scores for charts
    quiz_labels = [
        Quiz.query.get(s.quiz_id).name for s in scores if Quiz.query.get(s.quiz_id)
    ]
    quiz_scores = [s.total_scored for s in scores]

    return render_template(
        "user_dashboard.html",
        quizzes=all_quizzes,  # ✅ Added for feedback dropdown
        quiz_labels=quiz_labels,
        quiz_scores=quiz_scores,
        completed=completed,
        pending=pending,
        in_progress=in_progress,
    )


# ---------------- PLACEHOLDER ROUTES FOR MENU ----------------
@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    return render_template("placeholder.html", title="Manage Users")


@app.route("/admin/users/add", methods=["GET", "POST"])
@login_required
def admin_add_user():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    return render_template("placeholder.html", title="Add User")


@app.route("/admin/analytics")
@login_required
def analytics():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    return render_template("placeholder.html", title="Analytics")


@app.route("/admin/settings")
@login_required
def settings():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    return render_template("placeholder.html", title="Settings")


@app.route("/admin/reports")
@login_required
def reports():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    return render_template("placeholder.html", title="Reports")


# ---------------- SUBJECT LIST FOR USERS ----------------
@app.route("/user/subjects")
@login_required
def user_subjects():
    if current_user.role != "user":
        return redirect(url_for("admin_dashboard"))

    subjects = Subject.query.all()

    # Attach chapters to each subject
    for subj in subjects:
        subj.chapters = Chapter.query.filter_by(subject_id=subj.id).all()
        # keep only published quizzes inside chapters
        for ch in subj.chapters:
            ch.quizzes = [q for q in ch.quizzes if q.is_published]

    return render_template("user_subjects.html", subjects=subjects)


# ---------------- SUBJECT CRUD ----------------
@app.route("/admin/subjects/view")
@login_required
def view_subjects():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    subjects = Subject.query.all()
    return render_template("view_subjects.html", subjects=subjects)


@app.route("/admin/subjects/add", methods=["GET", "POST"])
@login_required
def add_subject():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        desc = request.form.get("description", "").strip()

        if not name:
            flash("⚠️ Subject name is required.", "warning")
            return redirect(url_for("admin_dashboard"))

        if Subject.query.filter_by(name=name).first():
            flash("⚠️ Subject already exists.", "warning")
            return redirect(url_for("add_subject"))

        subject = Subject(name=name, description=desc)
        db.session.add(subject)
        db.session.commit()
        flash(f"✅ Subject '{name}' added successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_subject.html")


@app.route("/admin/subjects/edit/<int:subject_id>", methods=["GET", "POST"])
@login_required
def edit_subject(subject_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    subject = Subject.query.get_or_404(subject_id)

    if request.method == "POST":
        subject.name = request.form.get("name", "").strip()
        subject.description = request.form.get("description", "").strip()
        db.session.commit()
        flash("✅ Subject updated successfully!", "success")
        return redirect(url_for("view_subjects"))  # <-- FIXED

    return render_template("edit_subject.html", subject=subject)


@app.route("/admin/subjects/delete/<int:subject_id>", methods=["POST"])
@login_required
def delete_subject(subject_id):
    if current_user.role != "admin":
        flash("Unauthorized access", "danger")
        return redirect(url_for("user_dashboard"))

    subject = Subject.query.get_or_404(subject_id)
    db.session.delete(subject)
    db.session.commit()

    flash("Subject deleted successfully!", "success")
    return redirect(url_for("admin_dashboard"))


# ---------------- CHAPTER CRUD ----------------
@app.route("/admin/chapters/<int:subject_id>")
@login_required
def manage_chapters(subject_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    subject = Subject.query.get_or_404(subject_id)
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    return render_template("view_chapters.html", subject=subject, chapters=chapters)


# ---------------- ADD CHAPTER - CHOOSE SUBJECT FIRST ----------------
@app.route("/admin/chapters/add", methods=["GET", "POST"])
@login_required
def add_chapter_choose_subject():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    subjects = Subject.query.all()

    if request.method == "POST":
        subject_id = request.form.get("subject_id")
        if not subject_id:
            flash("⚠️ Please select a subject.", "warning")
            return redirect(url_for("add_chapter_choose_subject"))
        return redirect(url_for("add_chapter", subject_id=subject_id))

    return render_template("add_chapter_choose_subject.html", subjects=subjects)


@app.route("/admin/chapters/view/<int:subject_id>")
@login_required
def view_chapters(subject_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    subject = Subject.query.get_or_404(subject_id)
    chapters = Chapter.query.filter_by(subject_id=subject.id).all()

    return render_template("view_chapters.html", subject=subject, chapters=chapters)


@app.route("/admin/chapters/add/<int:subject_id>", methods=["GET", "POST"])
@login_required
def add_chapter(subject_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    subject = Subject.query.get_or_404(subject_id)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        desc = request.form.get("description", "").strip()

        if not name:
            flash("⚠️ Chapter name cannot be empty.", "danger")
            return redirect(url_for("add_chapter", subject_id=subject_id))

        chapter = Chapter(name=name, description=desc, subject_id=subject_id)
        db.session.add(chapter)
        db.session.commit()
        flash(f"✅ Chapter '{name}' added successfully!", "success")
        return redirect(url_for("view_chapters", subject_id=subject_id))

    return render_template(
        "add_chapter.html",
        subject=subject,
        subject_id=subject_id,  # ✅ Added so Jinja can use it
    )


@app.route("/admin/chapters/edit/<int:chapter_id>", methods=["GET", "POST"])
@login_required
def edit_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    if request.method == "POST":
        chapter.name = request.form.get("name", "").strip()
        chapter.description = request.form.get("description", "").strip()
        db.session.commit()
        flash("Chapter updated successfully!", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("edit_chapter.html", chapter=chapter)


@app.route("/admin/chapters/delete/<int:chapter_id>")
@login_required
def delete_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    db.session.delete(chapter)
    db.session.commit()
    flash("Chapter deleted successfully!", "danger")
    return redirect(url_for("admin_dashboard"))


# ---------------- QUIZ CRUD ----------------
@app.route("/admin/quizzes/<int:chapter_id>")
@login_required
def manage_quizzes(chapter_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
    return render_template("manage_quizzes.html", chapter=chapter, quizzes=quizzes)


@app.route("/admin/quizzes/view/<int:chapter_id>")
@login_required
def view_quizzes(chapter_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter.id).all()
    return render_template("view_quizzes.html", chapter=chapter, quizzes=quizzes)


@app.route("/admin/quizzes/add/<int:chapter_id>", methods=["GET", "POST"])
@login_required
def add_quiz(chapter_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    chapter = Chapter.query.get_or_404(chapter_id)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        date = request.form.get("date_of_quiz", "")
        duration = request.form.get("time_duration", "")
        remarks = request.form.get("remarks", "")
        quiz = Quiz(
            name=name,
            date_of_quiz=date,
            time_duration=duration,
            remarks=remarks,
            chapter_id=chapter_id,
        )
        quiz.is_published = "is_published" in request.form
        db.session.add(quiz)
        db.session.commit()
        flash(f"✅ Quiz '{name}' added successfully!", "success")
        return redirect(url_for("manage_quizzes", chapter_id=chapter_id))
    return render_template("add_quiz.html", chapter=chapter, chapter_id=chapter_id)


@app.route("/admin/quizzes/edit/<int:quiz_id>", methods=["GET", "POST"])
@login_required
def edit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    if request.method == "POST":
        quiz.name = request.form["name"]
        quiz.date_of_quiz = request.form.get("date_of_quiz")
        quiz.time_duration = request.form.get("time_duration")
        quiz.remarks = request.form.get("remarks")
        quiz.is_published = "is_published" in request.form
        db.session.commit()
        flash("Quiz updated successfully!", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("edit_quiz.html", quiz=quiz)


@app.route("/admin/quizzes/delete/<int:quiz_id>")
@login_required
def delete_quiz(quiz_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    quiz = Quiz.query.get_or_404(quiz_id)
    db.session.delete(quiz)
    db.session.commit()
    flash("Quiz deleted successfully!", "danger")
    return redirect(url_for("admin_dashboard"))


# ---------------- QUESTION CRUD ----------------
@app.route("/admin/questions/<int:quiz_id>")
@login_required
def manage_questions(quiz_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return render_template("questions.html", quiz=quiz, questions=questions)


@app.route("/admin/questions/add/<int:quiz_id>", methods=["GET", "POST"])
@login_required
def add_question(quiz_id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    quiz = Quiz.query.get_or_404(quiz_id)

    if request.method == "POST":
        question_statement = request.form.get("question_statement", "").strip()
        option1 = request.form.get("option1", "").strip()
        option2 = request.form.get("option2", "").strip()
        option3 = request.form.get("option3", "").strip()
        option4 = request.form.get("option4", "").strip()
        correct_option = int(request.form["correct_option"])  # 1–4

        question = Question(
            question_statement=question_statement,
            option1=option1,
            option2=option2,
            option3=option3,
            option4=option4,
            correct_option=correct_option,
            quiz_id=quiz.id,
        )
        db.session.add(question)
        db.session.commit()
        flash("Question added successfully!", "success")
        return redirect(url_for("manage_questions", quiz_id=quiz.id))

    return render_template("add_question.html", quiz=quiz)


@app.route("/admin/questions/<int:quiz_id>/delete/<int:id>")
@login_required
def delete_question(quiz_id, id):
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    question = Question.query.get_or_404(id)

    if question.quiz_id != quiz_id:
        flash("Invalid operation.", "danger")
        return redirect(url_for("manage_questions", quiz_id=quiz_id))

    db.session.delete(question)
    db.session.commit()
    flash("Question deleted successfully!", "success")

    return redirect(url_for("manage_questions", quiz_id=quiz_id))


# ---------------- QUIZ ATTEMPT (USER) ----------------
@app.route("/user/quiz/<int:quiz_id>", methods=["GET", "POST"])
@login_required
def attempt_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    # ✅ Prevent multiple attempts
    existing_score = Score.query.filter_by(
        user_id=current_user.id, quiz_id=quiz_id
    ).first()
    if existing_score:
        flash(
            "⚠️ You have already attempted this quiz. You cannot retake it.", "warning"
        )
        return redirect(url_for("user_scores"))

    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    question_list = []
    for q in questions:
        question_list.append(
            {
                "id": q.id,
                "statement": q.question_statement,
                "option1": q.option1,
                "option2": q.option2,
                "option3": q.option3,
                "option4": q.option4,
                "correct_option": q.correct_option,
            }
        )

    try:
        duration = int(quiz.time_duration.split()[0]) if quiz.time_duration else 1
    except ValueError:
        duration = 1

    if request.method == "POST":
        score = 0
        new_score = Score(
            quiz_id=quiz_id,
            user_id=current_user.id,
            total_scored=0,
            total_questions=len(question_list),
        )
        db.session.add(new_score)
        db.session.commit()

        # ✅ Save user answers
        for q in question_list:
            selected = request.form.get(f"q{q['id']}")
            if selected:
                selected = int(selected)
                if selected == q["correct_option"]:
                    score += 1
                ua = UserAnswer(
                    score_id=new_score.id,
                    question_id=q["id"],
                    selected_option=selected,
                )
                db.session.add(ua)

        new_score.total_scored = score
        db.session.commit()

        flash(f"✅ You scored {score}/{len(question_list)}!", "info")
        return redirect(url_for("user_scores"))

    return render_template(
        "attempt_quiz.html", quiz=quiz, questions=question_list, duration=duration
    )


# ---------------- USER QUIZ LIST ----------------
@app.route("/user/quizzes")
@login_required
def user_quizzes():
    if current_user.role != "user":
        return redirect(url_for("admin_dashboard"))

    subjects = Subject.query.all()

    # Keep only published quizzes for each chapter
    for subject in subjects:
        for chapter in subject.chapters:
            chapter.quizzes = [q for q in chapter.quizzes if q.is_published]

    return render_template("user_quizzes.html", subjects=subjects)


# ---------------- SCORES ----------------
@app.route("/user/scores")
@login_required
def user_scores():
    scores = Score.query.filter_by(user_id=current_user.id).all()
    return render_template("user_scores.html", scores=scores)


# ---------------- EXPORT ANSWERS (PDF & EXCEL) ----------------
@app.route("/user/export_answers_pdf/<int:score_id>")
@login_required
def export_answers_pdf(score_id):
    score = Score.query.get_or_404(score_id)
    if score.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for("user_scores"))

    quiz = Quiz.query.get(score.quiz_id)  # ✅ FIX: fetch quiz manually

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, 750, f"Quiz Answers Report - {quiz.name}")
    p.setFont("Helvetica", 12)
    p.drawString(100, 730, f"User: {current_user.full_name}")
    p.drawString(100, 710, f"Score: {score.total_scored}/{score.total_questions}")
    y = 680

    for ans in score.answers:
        q = ans.question
        p.setFont("Helvetica-Bold", 11)
        p.drawString(100, y, f"Q: {q.question_statement}")
        y -= 15
        options = [q.option1, q.option2, q.option3, q.option4]
        for i, opt in enumerate(options, 1):
            prefix = "  "
            if i == q.correct_option:
                prefix = "✔ Correct: "
            elif ans.selected_option == i:
                prefix = "✘ Your Answer: "
            p.setFont("Helvetica", 10)
            p.drawString(120, y, f"{prefix}{opt}")
            y -= 12
        y -= 8
        if y < 100:
            p.showPage()
            y = 750

    p.showPage()
    p.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="quiz_answers.pdf",
        mimetype="application/pdf",
    )


@app.route("/user/export_answers_excel/<int:score_id>")
@login_required
def export_answers_excel(score_id):
    score = Score.query.get_or_404(score_id)
    if score.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for("user_scores"))
    quiz = Quiz.query.get(score.quiz_id)  # ✅ FIX: fetch quiz manually

    wb = openpyxl.Workbook()
    sheet = wb.active
    sheet.title = "Quiz Answers"

    # ✅ Add metadata
    sheet.append(["Quiz:", quiz.name])
    sheet.append(["User:", current_user.full_name])
    sheet.append([f"Score: {score.total_scored}/{score.total_questions}"])
    sheet.append([])

    sheet.append(
        [
            "Question",
            "Option 1",
            "Option 2",
            "Option 3",
            "Option 4",
            "Correct Option",
            "Your Answer",
        ]
    )

    for ans in score.answers:
        q = ans.question
        sheet.append(
            [
                q.question_statement,
                q.option1,
                q.option2,
                q.option3,
                q.option4,
                q.correct_option,
                ans.selected_option,
            ]
        )

    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="quiz_answers.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.route("/user/view_answers/<int:score_id>")
@login_required
def view_answers(score_id):
    score = Score.query.get_or_404(score_id)

    # ✅ Security: only allow owner
    if score.user_id != current_user.id:
        flash("Unauthorized access!", "danger")
        return redirect(url_for("user_scores"))

    quiz = Quiz.query.get(score.quiz_id)

    # ✅ Build answers in correct format
    answers = [
        {
            "question": q.question_statement,
            "option1": q.option1,
            "option2": q.option2,
            "option3": q.option3,
            "option4": q.option4,
            "correct_option": q.correct_option,
            "user_answer": ans.selected_option,
        }
        for ans in score.answers
        for q in [ans.question]
    ]

    return render_template("view_answers.html", quiz=quiz, score=score, answers=answers)


@app.route("/admin/scores")
@login_required
def admin_scores():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    scores = Score.query.all()
    data = []
    for s in scores:
        user = User.query.get(s.user_id)
        quiz = Quiz.query.get(s.quiz_id)
        data.append(
            {
                "user": user.full_name if user else "Unknown",
                "quiz": f"Quiz {quiz.id}" if quiz else f"Quiz {s.quiz_id}",
                "score": f"{s.total_scored}/{s.total_questions}",
                "time": s.timestamp.strftime("%Y-%m-%d %H:%M") if s.timestamp else "",
                "score_id": s.id,
            }
        )
    return render_template("admin_scores.html", scores=data)


# ---------------- ADMIN EXPORT SCORES (XLSX & CSV) ----------------
def _gather_scores_for_export():
    """
    Returns a list of dict rows ready to be written to CSV/XLSX.
    Each row contains:
    - score_id, user_id, user_name, user_email, quiz_id, quiz_name,
      subject_name, chapter_name, scored, total_questions, timestamp
    """
    rows = []
    scores = Score.query.order_by(Score.timestamp).all()
    for s in scores:
        user = User.query.get(s.user_id)
        quiz = Quiz.query.get(s.quiz_id)

        subject_name = ""
        chapter_name = ""
        if quiz:
            chapter = Chapter.query.get(quiz.chapter_id) if quiz.chapter_id else None
            if chapter:
                chapter_name = chapter.name
                subj = (
                    Subject.query.get(chapter.subject_id)
                    if chapter.subject_id
                    else None
                )
                if subj:
                    subject_name = subj.name

        rows.append(
            {
                "score_id": s.id,
                "user_id": user.id if user else "",
                "user_name": user.full_name if user else "Unknown",  # ✅ consistent key
                "user_email": user.email if user else "",
                "quiz_id": quiz.id if quiz else "",
                "quiz_name": quiz.name if quiz else "",
                "subject_name": subject_name,
                "chapter_name": chapter_name,
                "scored": s.total_scored,
                "total_questions": s.total_questions,
                "timestamp": (
                    s.timestamp.strftime("%Y-%m-%d %H:%M") if s.timestamp else ""
                ),
            }
        )
    return rows


@app.route("/admin/export_scores_excel")
@login_required
def admin_export_scores_excel():
    if current_user.role != "admin":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("user_dashboard"))

    rows = _gather_scores_for_export()
    if not rows:
        flash("No scores available to export.", "warning")
        return redirect(url_for("view_scores"))

    wb = openpyxl.Workbook()
    sheet = wb.active
    sheet.title = "All Quiz Results"

    # ✅ Use consistent headers
    header = [
        "Score ID",
        "User ID",
        "User Full Name",
        "User Email",
        "Quiz ID",
        "Quiz Name",
        "Subject",
        "Chapter",
        "Scored",
        "Total Questions",
        "Timestamp (ISO)",
    ]
    sheet.append(header)

    for r in rows:
        sheet.append(
            [
                r.get("score_id", ""),
                r.get("user_id", ""),
                r.get("user_name", ""),
                r.get("user_email", ""),
                r.get("quiz_id", ""),
                r.get("quiz_name", ""),
                r.get("subject_name", ""),
                r.get("chapter_name", ""),
                r.get("scored", ""),
                r.get("total_questions", ""),
                r.get("timestamp", ""),
            ]
        )

    # ✅ Auto-size columns
    for column_cells in sheet.columns:
        length = max(
            (len(str(cell.value)) for cell in column_cells if cell.value), default=0
        )
        adjusted_width = length + 2
        sheet.column_dimensions[column_cells[0].column_letter].width = adjusted_width

    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    filename = f"all_quiz_results_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.xlsx"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.route("/admin/export_scores_csv")
@login_required
def admin_export_scores_csv():
    if current_user.role != "admin":
        flash("Unauthorized access!", "danger")
        return redirect(url_for("user_dashboard"))

    rows = _gather_scores_for_export()
    if not rows:
        flash("No scores available to export.", "warning")
        return redirect(url_for("view_scores"))

    si = io.StringIO()
    writer = csv.writer(si)

    # ✅ Consistent headers
    header = [
        "Score ID",
        "User ID",
        "User Full Name",
        "User Email",
        "Quiz ID",
        "Quiz Name",
        "Subject",
        "Chapter",
        "Scored",
        "Total Questions",
        "Timestamp (ISO)",
    ]
    writer.writerow(header)

    for r in rows:
        writer.writerow(
            [
                r.get("score_id", ""),
                r.get("user_id", ""),
                r.get("user_name", ""),
                r.get("user_email", ""),
                r.get("quiz_id", ""),
                r.get("quiz_name", ""),
                r.get("subject_name", ""),
                r.get("chapter_name", ""),
                r.get("scored", ""),
                r.get("total_questions", ""),
                r.get("timestamp", ""),
            ]
        )

    mem = io.BytesIO()
    mem.write(si.getvalue().encode("utf-8"))
    mem.seek(0)

    filename = f"all_quiz_results_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.csv"
    return send_file(
        mem,
        as_attachment=True,
        download_name=filename,
        mimetype="text/csv",
    )


# ---------------- SCORE SUMMARY (UPDATED) ----------------
@app.route("/user/score_summary")
@login_required
def score_summary():
    if current_user.role != "user":
        return redirect(url_for("admin_dashboard"))

    summary = []
    subjects = Subject.query.all()

    for subj in subjects:
        subj_total_scored = 0
        subj_total_questions = 0
        chapters_data = []

        for ch in subj.chapters:
            scores = (
                Score.query.join(Quiz)
                .filter(Score.user_id == current_user.id, Quiz.chapter_id == ch.id)
                .all()
            )
            if scores:
                scored = sum(s.total_scored for s in scores)
                total = sum(s.total_questions for s in scores)
                subj_total_scored += scored
                subj_total_questions += total
                chapters_data.append(
                    {"chapter": ch.name, "scored": scored, "total": total}
                )

        if chapters_data:
            percent = (
                int((subj_total_scored / subj_total_questions) * 100)
                if subj_total_questions > 0
                else 0
            )
            summary.append(
                {
                    "subject": subj.name,
                    "total_score": subj_total_scored,
                    "total_questions": subj_total_questions,
                    "percent": percent,
                    "chapters": chapters_data,
                }
            )

    return render_template("score_summary.html", summary=summary)


# ---------------- PLACEHOLDER TEMPLATE FALLBACK ----------------
@app.route("/placeholder")
def placeholder():
    return render_template("placeholder.html", title="Coming Soon!")


@app.route("/admin/view_scores")
@login_required
def view_scores():
    if current_user.role != "admin":
        flash("Unauthorized access", "danger")
        return redirect(
            url_for("admin_dashboard")
        )  # ⚠️ Change "index" → "admin_dashboard" if index doesn’t exist

    scores = (
        db.session.query(
            Score.total_scored,
            Score.total_questions,
            Score.timestamp,
            User.full_name.label("user_name"),
            User.email.label("user_email"),
            Subject.name.label("subject_name"),
            Chapter.name.label("chapter_name"),
            Quiz.name.label("quiz_name"),
        )
        .join(User, Score.user_id == User.id)
        .join(Quiz, Score.quiz_id == Quiz.id)
        .join(Chapter, Quiz.chapter_id == Chapter.id)
        .join(Subject, Chapter.subject_id == Subject.id)
        .all()
    )
    return render_template("view_scores.html", scores=scores)


@app.route("/admin/choose_subject_for_chapters")
def choose_subject_for_chapters():
    subjects = Subject.query.all()
    return render_template("choose_subject_for_chapters.html", subjects=subjects)


@app.route("/admin/choose_subject_for_quizzes")
def choose_subject_for_quizzes():
    subjects = Subject.query.all()
    return render_template("choose_subject_for_quizzes.html", subjects=subjects)


@app.route("/admin/quizzes/add", methods=["GET"])
@login_required
def choose_subject_for_add_quiz():
    subjects = Subject.query.all()
    return render_template("choose_subject_for_add_quiz.html", subjects=subjects)


@app.route("/admin/users/view")
@login_required
def view_users():
    users = User.query.all()  # fetch all users from DB
    return render_template("view_users.html", users=users)


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def admin_delete_user(user_id):
    if current_user.role != "admin":
        flash("Unauthorized access.", "danger")
        return redirect(url_for("user_dashboard"))

    user = User.query.get_or_404(user_id)
    if user.role == "admin":
        flash("⚠️ You cannot delete another admin.", "warning")
        return redirect(url_for("admin_users"))

    user_name = user.full_name

    db.session.delete(user)
    db.session.commit()
    flash(f"🗑️ User {user_name} has been deleted successfully.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/feedbacks")
@login_required
def admin_feedbacks():
    if current_user.role != "admin":
        return redirect(url_for("user_dashboard"))

    feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).all()

    # Optional debug print
    RATING_MAP = {
        1: "Very Difficult",
        2: "Difficult",
        3: "Average",
        4: "Easy",
        5: "Very Easy",
    }
    for fb in feedbacks:
        rating_text = RATING_MAP.get(fb.rating, "N/A")
        print(
            f"Feedback ID: {fb.id}, "
            f"User: {fb.user.full_name if fb.user else 'N/A'}, "
            f"Quiz: {fb.quiz.name if fb.quiz else 'General'}, "
            f"Comment: {fb.comment}, "
            f"Rating: {rating_text}"
        )

    return render_template(
        "admin_feedbacks.html", feedbacks=feedbacks, rating_map=RATING_MAP
    )


@app.route("/submit_feedback", methods=["POST"])
@login_required
def submit_feedback():
    feedback_type = request.form.get("feedback_type")
    quiz_id = request.form.get("quiz_id") if feedback_type == "quiz" else None
    rating = request.form.get("rating")
    comment = request.form.get("comment")

    new_feedback = Feedback(
        quiz_id=quiz_id if quiz_id else None,
        user_id=current_user.id,
        rating=int(rating),
        comment=comment,
    )
    db.session.add(new_feedback)
    db.session.commit()

    flash("✅ Feedback submitted successfully!", "success")
    return redirect(url_for("user_dashboard"))


if __name__ == "__main__":
    app.run(debug=True)
