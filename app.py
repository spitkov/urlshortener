from flask import Flask, request, redirect, render_template, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from functools import wraps
import string
import random
import os
import uuid
import json
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    api_key = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))

    def set_password(self, password):
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        self.password_hash = salt.hex() + ':' + key.hex()

    def check_password(self, password):
        salt, key = self.password_hash.split(':')
        return key == hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 100000).hex()

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500), nullable=False)
    short_url = db.Column(db.String(10), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('urls', lazy=True))

    def set_password(self, password):
        if password:
            salt = os.urandom(32)
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            self.password_hash = salt.hex() + ':' + key.hex()
        else:
            self.password_hash = None

    def check_password(self, password):
        if self.password_hash:
            salt, key = self.password_hash.split(':')
            return key == hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 100000).hex()
        return True

def generate_short_url(length=6):
    characters = string.ascii_letters + string.digits
    while True:
        short_url = ''.join(random.choice(characters) for _ in range(length))
        if not URL.query.filter_by(short_url=short_url).first():
            return short_url

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user = User.query.get(session.get('user_id')) if 'user_id' in session else None
        return create_short_url(request.form, user)
    return render_template('index.html')

@app.route('/<short_url>', methods=['GET', 'POST'])
def redirect_to_url(short_url):
    url = URL.query.filter_by(short_url=short_url).first_or_404()
    user = User.query.get(url.user_id)
    uploader = user.username if user else "Anonymous"
    is_password_protected = bool(url.password_hash)
    
    if is_password_protected:
        if request.method == 'POST':
            if url.check_password(request.form.get('password')):
                return render_template('redirect.html', url=url, uploader=uploader, is_password_protected=is_password_protected)
            else:
                flash('Incorrect password', 'danger')
        return render_template('password_prompt.html', short_url=short_url)
    return render_template('redirect.html', url=url, uploader=uploader, is_password_protected=is_password_protected)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html')
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        session['user_id'] = new_user.id
        session['username'] = new_user.username
        
        flash('Registration successful! You are now logged in.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    user_urls = URL.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', urls=user_urls, api_key=user.api_key)

@app.route('/delete/<int:url_id>')
@login_required
def delete_url(url_id):
    url = URL.query.get_or_404(url_id)
    if url.user_id != session['user_id']:
        flash('You do not have permission to delete this URL.', 'danger')
        return redirect(url_for('dashboard'))
    db.session.delete(url)
    db.session.commit()
    flash('URL deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/edit_url/<int:url_id>', methods=['GET', 'POST'])
@login_required
def edit_url(url_id):
    url = URL.query.get_or_404(url_id)
    
    if url.user_id != session['user_id']:
        flash('You do not have permission to edit this URL.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        original_url = request.form['original_url']
        short_url = request.form['short_url']
        password = request.form['password']
        
        existing_url = URL.query.filter_by(short_url=short_url).first()
        if existing_url and existing_url.id != url.id:
            flash('Custom vanity URL is already in use. Please choose another one.', 'danger')
        else:
            url.original_url = original_url
            url.short_url = short_url
            url.set_password(password)
            db.session.commit()
            flash('URL updated successfully.', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('edit_url.html', url=url)

@app.route('/reset_api_key')
@login_required
def reset_api_key():
    user = User.query.get(session['user_id'])
    user.api_key = str(uuid.uuid4())
    db.session.commit()
    flash('API key has been reset.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download_sharex_config')
@login_required
def download_sharex_config():
    user = User.query.get(session['user_id'])
    config = {
        "Version": "13.7.0",
        "Name": "Your URL Shortener",
        "DestinationType": "URLShortener",
        "RequestMethod": "POST",
        "RequestURL": url_for('api_shorten_url', _external=True),
        "Headers": {
            "Authorization": user.api_key
        },
        "Body": "JSON",
        "Data": "{\"url\":\"$input$\"}",
        "URL": "$json:short_url$"
    }
    return app.response_class(
        json.dumps(config, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=url_shortener_config.sxcu'}
    )

@app.route('/api/shorten', methods=['POST'])
def api_shorten_url():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        user = User.query.filter_by(api_key=auth_header).first()
        if not user:
            return jsonify({"error": "Invalid API key"}), 401
    else:
        user = User.query.get(session.get('user_id', 1))

    data = request.json or request.form
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    return create_short_url(data, user)

def create_short_url(data, user=None):
    original_url = data['url']
    custom_vanity = data.get('vanity')
    password = data.get('password')

    if not original_url.startswith(('http://', 'https://')):
        original_url = 'https://' + original_url

    if custom_vanity:
        if URL.query.filter_by(short_url=custom_vanity).first():
            return jsonify({"error": "Custom vanity URL is already in use"}), 400
        short_url = custom_vanity
    else:
        short_url = generate_short_url()

    user_id = session.get('user_id', 1)

    new_url = URL(original_url=original_url, short_url=short_url, user_id=user_id)
    if password:
        new_url.set_password(password)
    db.session.add(new_url)
    db.session.commit()

    short_url_full = url_for('redirect_to_url', short_url=short_url, _external=True, _scheme='https')
    if request.is_json:
        return jsonify({
            "original_url": original_url,
            "short_url": short_url_full
        }), 201
    else:
        return render_template('index.html', short_url=short_url_full)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True,host='0.0.0.0',port=6601)
