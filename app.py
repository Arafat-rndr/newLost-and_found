from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import os
from dotenv import load_dotenv

# ----------------------
# LOAD ENVIRONMENT VARIABLES
# ----------------------
load_dotenv()

# ----------------------
# FLASK APP SETUP
# ----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key_here')

# ----------------------
# DATABASE CONFIG
# ----------------------
db_url = os.getenv('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload folder
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ----------------------
# FLASK-MAIL CONFIG
# ----------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

mail = Mail(app)

# ----------------------
# DATABASE SETUP
# ----------------------
db = SQLAlchemy(app)

# ----------------------
# FLASK-LOGIN SETUP
# ----------------------
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ======================
# DATABASE MODELS
# ======================
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    profile_pic = db.Column(db.String(200), default="default.png")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)

    items = db.relationship("Item", backref="user", lazy=True)
    notifications = db.relationship("Notification", backref="receiver", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Item(db.Model):
    __tablename__ = "items"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    location = db.Column(db.String(150), nullable=False)
    photo = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

class Notification(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

# ======================
# FLASK-WTF FORMS
# ======================
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email already exists.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ItemForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    category = SelectField('Category', choices=[('Electronics', 'Electronics'), ('Clothes', 'Clothes'), ('Other', 'Other')])
    status = SelectField('Status', choices=[('Lost', 'Lost'), ('Found', 'Found')])
    location = StringField('Location', validators=[DataRequired()])
    photo = FileField('Photo', validators=[FileAllowed(['jpg', 'jpeg', 'png'], 'Images only!')])
    submit = SubmitField('Report Item')

# ======================
# LOGIN REQUIREMENT
# ======================
@app.before_request
def require_login():
    allowed_routes = ['login', 'register', 'static']
    if request.endpoint not in allowed_routes and not current_user.is_authenticated:
        return redirect(url_for('login'))

# ======================
# ROUTES
# ======================
@app.route('/')
def home():
    return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()

        # Send verification email
        token = f"{new_user.id}-{new_user.email}"
        verify_url = url_for('verify_email', token=token, _external=True)
        msg = Message('Verify Your Email', recipients=[new_user.email])
        msg.body = f"Hi {new_user.username},\n\nPlease verify your email by clicking the following link:\n{verify_url}\n\nThanks!"
        mail.send(msg)

        flash('Account created! Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        user_id, email = token.split('-')
        user = User.query.get(int(user_id))
        if user and user.email == email:
            user.is_verified = True
            db.session.commit()
            flash('Email verified successfully!', 'success')
        else:
            flash('Invalid verification link.', 'danger')
    except:
        flash('Invalid token.', 'danger')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ======================
# DASHBOARD ROUTE
# ======================
@app.route('/dashboard')
@login_required
def dashboard():
    items = Item.query.filter_by(user_id=current_user.id).order_by(Item.created_at.desc()).all()
    notifications = Notification.query.filter_by(receiver_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('dashboard.html', items=items, notifications=notifications)

# ======================
# REPORT ROUTE
# ======================
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    form = ItemForm()
    if form.validate_on_submit():
        photo_filename = None
        if form.photo.data:
            photo_filename = secure_filename(form.photo.data.filename)
            form.photo.data.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_filename))

        new_item = Item(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            status=form.status.data,
            location=form.location.data,
            photo=photo_filename,
            user_id=current_user.id
        )
        db.session.add(new_item)
        db.session.commit()

        # If FOUND, notify owners of matching LOST items
        if new_item.status == 'Found':
            lost_items = Item.query.filter_by(title=new_item.title, status='Lost').all()
            for lost_item in lost_items:
                message_text = f"Your lost item '{lost_item.title}' has been reported as FOUND by {current_user.username}."
                notification = Notification(message=message_text, receiver_id=lost_item.user_id)
                db.session.add(notification)

                owner = User.query.get(lost_item.user_id)
                if owner.is_verified:
                    try:
                        msg = Message('Lost Item Found Notification', recipients=[owner.email])
                        msg.body = f"Hi {owner.username},\n\n{message_text}\n\nCheck your dashboard for more details."
                        mail.send(msg)
                    except Exception as e:
                        print(f"Failed to send email: {e}")

            db.session.commit()

        flash('Item reported successfully!', 'success')
        return redirect(url_for('dashboard'))

    items = Item.query.filter_by(user_id=current_user.id).order_by(Item.created_at.desc()).all()
    return render_template('report.html', form=form, items=items)

# ======================
# FILTER ITEMS ROUTE
# ======================
@app.route('/items/<status>')
@login_required
def filter_items(status):
    if status not in ['Lost', 'Found']:
        flash('Invalid item status.', 'danger')
        return redirect(url_for('dashboard'))

    items = Item.query.filter_by(user_id=current_user.id, status=status).order_by(Item.created_at.desc()).all()
    notifications = Notification.query.filter_by(receiver_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('dashboard.html', items=items, notifications=notifications)

# ======================
# VIEW ALL NOTIFICATIONS
# ======================
@app.route('/notifications')
@login_required
def notifications():
    all_notifications = Notification.query.filter_by(receiver_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=all_notifications)

# ======================
# TEST EMAIL ROUTE
# ======================
@app.route('/test-email')
def test_email():
    try:
        msg = Message(
            subject="Test Email from Flask",
            recipients=[os.getenv('MAIL_USERNAME')],
            body="This is a test email to check Flask-Mail setup."
        )
        mail.send(msg)
        return "Test email sent! Check your inbox."
    except Exception as e:
        return f"Error sending email: {e}"

# ======================
# RUN APP
# ======================
if __name__ == '__main__':
    app.run(debug=True)
