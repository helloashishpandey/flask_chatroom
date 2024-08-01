from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message as MailMessage
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False').lower() == 'true'

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(150), nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    message = db.Column(db.String(500), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.email_verified:
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Email not verified. Please check your inbox.', 'danger')
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            verification_token = str(uuid.uuid4())
            new_user = User(
                username=username,
                password=hashed_password,
                email=email,
                email_verification_token=verification_token
            )
            db.session.add(new_user)
            db.session.commit()
            
            verification_link = url_for('verify_email', token=verification_token, _external=True)
            msg = MailMessage('Email Verification', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Please click the link to verify your email: {verification_link}'
            mail.send(msg)

            flash('Account created successfully. Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    user = User.query.filter_by(email_verification_token=token).first()
    if user:
        user.email_verified = True
        user.email_verification_token = None
        db.session.commit()
        flash('Email verified successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('index'))

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create_room')
@login_required
def create_room():
    room_id = str(uuid.uuid4())
    return redirect(url_for('chat_room', room_id=room_id))

@app.route('/room/<room_id>')
@login_required
def chat_room(room_id):
    messages = Message.query.filter_by(room=room_id).all()
    return render_template('chat_room.html', room_id=room_id, messages=messages)

@socketio.on('join')
def on_join(data):
    username = current_user.username
    room = data['room']
    join_room(room)
    send(f'{username} has entered the room.', to=room)

@socketio.on('leave')
def on_leave(data):
    username = current_user.username
    room = data['room']
    leave_room(room)
    send(f'{username} has left the room.', to=room)

@socketio.on('message')
def handle_message(data):
    room = data['room']
    message = data['message']
    username = current_user.username
    new_message = Message(room=room, username=username, message=message)
    db.session.add(new_message)
    db.session.commit()
    send(f'{username}: {message}', to=room)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)

