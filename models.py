from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(120))
    qualification = db.Column(db.String(120))
    dob = db.Column(db.String(20))
    role = db.Column(db.String(10), default="user")  # "admin" or "user"
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime, default=None)
    profile_picture = db.Column(db.String(200), default=None)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    chapters = db.relationship(
        "Chapter", backref="subject", cascade="all, delete-orphan"
    )


class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey("subject.id"))
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    quizzes = db.relationship("Quiz", backref="chapter", cascade="all, delete-orphan")


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    date_of_quiz = db.Column(db.String(20))
    time_duration = db.Column(db.String(10))
    remarks = db.Column(db.Text)
    chapter_id = db.Column(db.Integer, db.ForeignKey("chapter.id"))
    questions = db.relationship(
        "Question", backref="quiz", cascade="all, delete-orphan"
    )
    is_published = db.Column(db.Boolean, default=False)


class Question(db.Model):
    __tablename__ = "question"

    id = db.Column(db.Integer, primary_key=True)
    question_statement = db.Column(db.Text, nullable=False)  # Question text
    option1 = db.Column(db.String(200), nullable=False)
    option2 = db.Column(db.String(200), nullable=False)
    option3 = db.Column(db.String(200), nullable=False)
    option4 = db.Column(db.String(200), nullable=False)
    correct_option = db.Column(db.Integer, nullable=False)
    # stores index: 1, 2, 3, or 4 (refers to option1–option4)
    difficulty = db.Column(db.String(20), nullable=False, default="Easy")
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"), nullable=False)


class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    total_scored = db.Column(db.Integer)
    total_questions = db.Column(db.Integer)

    # ✅ one attempt can have multiple answers
    answers = db.relationship(
        "UserAnswer", backref="score", cascade="all, delete-orphan"
    )
    quiz = db.relationship("Quiz", backref="scores")


class UserAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    score_id = db.Column(db.Integer, db.ForeignKey("score.id"))
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"))
    selected_option = db.Column(db.Integer)  # what user chose

    # ✅ relationships for easy access
    question = db.relationship("Question")


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1–5 scale for difficulty
    comment = db.Column(db.Text, nullable=True)  # optional feedback
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationships
    quiz = db.relationship("Quiz", backref=db.backref("feedbacks", lazy=True))
    user = db.relationship("User", backref=db.backref("feedbacks", lazy=True))
