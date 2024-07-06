from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import string
import random
from datetime import datetime
import time
from collections import deque

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500), nullable=False)
    short_url = db.Column(db.String(6), unique=True, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class RateLimiter:
    def __init__(self, max_requests, window_size):
        self.max_requests = max_requests
        self.window_size = window_size
        self.requests = {}

    def is_allowed(self, client_id):
        current_time = time.time()
        if client_id not in self.requests:
            self.requests[client_id] = deque()

        self.requests[client_id] = deque([t for t in self.requests[client_id] if current_time - t < self.window_size])

        if len(self.requests[client_id]) < self.max_requests:
            self.requests[client_id].append(current_time)
            return True
        return False

rate_limiter = RateLimiter(max_requests=5, window_size=60)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_short_url():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(6))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
            return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/shorten', methods=['POST'])
@login_required
def shorten_url():
    if not rate_limiter.is_allowed(current_user.id):
        flash('Rate limit exceeded. Please try again later.')
        return redirect(url_for('home'))

    original_url = request.form['url']
    short_url = generate_short_url()
    new_url = URL(original_url=original_url, short_url=short_url, user_id=current_user.id)
    db.session.add(new_url)
    db.session.commit()
    flash(f'Shortened URL: {request.host_url}{short_url}')
    return redirect(url_for('home'))

@app.route('/<short_url>')
def redirect_to_url(short_url):
    url = URL.query.filter_by(short_url=short_url).first_or_404()
    return redirect(url.original_url)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)