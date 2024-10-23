from flask import Flask, request, redirect, render_template, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import string
import random
from functools import wraps
import os
import hashlib
import uuid
import json
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Use a strong, random secret key in production
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
        self.password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000).hex() + ':' + salt.hex()

    def check_password(self, password):
        stored_hash, salt = self.password_hash.split(':')
        computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 100000).hex()
        return stored_hash == computed_hash

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500), nullable=False)
    short_url = db.Column(db.String(10), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('urls', lazy=True))

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
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        original_url = request.form['url']
        custom_vanity = request.form.get('vanity')
        
        # Add protocol if it's missing
        if not original_url.startswith(('http://', 'https://')):
            original_url = 'https://' + original_url
        
        if custom_vanity:
            if URL.query.filter_by(short_url=custom_vanity).first():
                flash('Custom vanity URL is already in use. Please choose another one.', 'danger')
                return render_template('index.html')
            short_url = custom_vanity
        else:
            short_url = generate_short_url()
        
        new_url = URL(original_url=original_url, short_url=short_url, user_id=session.get('user_id', 1))
        db.session.add(new_url)
        db.session.commit()
        return render_template('index.html', short_url=short_url)
    return render_template('index.html')

@app.route('/<short_url>')
def redirect_to_url(short_url):
    url = URL.query.filter_by(short_url=short_url).first_or_404()
    return redirect(url.original_url)

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
        
        # Automatically log in the user
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
    user_urls = URL.query.filter_by(user_id=session['user_id']).all()
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
        
        existing_url = URL.query.filter_by(short_url=short_url).first()
        if existing_url and existing_url.id != url.id:
            flash('Custom vanity URL is already in use. Please choose another one.', 'danger')
        else:
            url.original_url = original_url
            url.short_url = short_url
            db.session.commit()
            flash('URL updated successfully.', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('edit_url.html', url=url)

@app.cli.command("migrate_passwords")
def migrate_passwords():
    with app.app_context():
        users = User.query.all()
        for user in users:
            if hasattr(user, 'password') and user.password:
                user.set_password(user.password)
        db.session.commit()
    print("Passwords migrated successfully.")

def init_db():
    db_path = os.path.join(app.root_path, 'urls.db')
    if not os.path.exists(db_path):
        with app.app_context():
            db.create_all()
            print("Database created.")
    else:
        print("Database already exists.")
        # Add api_key column if it doesn't exist
        with app.app_context():
            if not hasattr(User, 'api_key'):
                with db.engine.connect() as conn:
                    conn.execute(text('ALTER TABLE user ADD COLUMN api_key VARCHAR(36) UNIQUE'))
                    conn.commit()
                print("Added api_key column to User table.")

@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Initialized the database.")

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
    if not auth_header:
        return jsonify({"error": "No API key provided"}), 401
    
    user = User.query.filter_by(api_key=auth_header).first()
    if not user:
        return jsonify({"error": "Invalid API key"}), 401
    
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400
    
    original_url = data['url']
    if not original_url.startswith(('http://', 'https://')):
        original_url = 'https://' + original_url
    
    short_url = generate_short_url()
    new_url = URL(original_url=original_url, short_url=short_url, user_id=user.id)
    db.session.add(new_url)
    db.session.commit()
    
    return jsonify({
        "original_url": original_url,
        "short_url": url_for('redirect_to_url', short_url=short_url, _external=True)
    }), 201

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
