from flask import Flask, request, redirect, render_template, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import string
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500), nullable=False)
    short_url = db.Column(db.String(10), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Associate URL with user

def generate_short_url(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        original_url = request.form['url']
        custom_vanity = request.form.get('vanity')
        
        # Check if a custom vanity is provided and is unique
        if custom_vanity:
            existing_url = URL.query.filter_by(short_url=custom_vanity).first()
            if existing_url:
                flash('Custom vanity URL is already in use. Please choose another one.', 'danger')
                return render_template('index.html')
            short_url = custom_vanity
        else:
            short_url = generate_short_url()  # Generate a random short URL if no custom vanity is provided
        
        new_url = URL(original_url=original_url, short_url=short_url, user_id=session.get('user_id'))  # Associate with logged-in user
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
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_urls = URL.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', urls=user_urls)

@app.route('/delete/<int:url_id>')
def delete_url(url_id):
    url = URL.query.get_or_404(url_id)
    if url.user_id != session.get('user_id'):
        flash('You do not have permission to delete this URL.', 'danger')
        return redirect(url_for('dashboard'))
    db.session.delete(url)
    db.session.commit()
    flash('URL deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove the user session
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))  # Redirect to the home page

@app.route('/edit_url', methods=['POST'])
def edit_url():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    url_id = request.form['url_id']
    original_url = request.form['original_url']
    short_url = request.form['short_url']
    
    url = URL.query.get_or_404(url_id)
    
    if url.user_id != session['user_id']:
        flash('You do not have permission to edit this URL.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check if the new short_url already exists
    existing_url = URL.query.filter_by(short_url=short_url).first()
    if existing_url and existing_url.id != url.id:  # Ensure it's not the same URL
        flash('Custom vanity URL is already in use. Please choose another one.', 'danger')
        # Render the dashboard with the modal open and pre-filled values
        user_urls = URL.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', urls=user_urls, original_url=original_url, short_url=short_url, url_id=url_id)

    # Update the URL
    url.original_url = original_url
    url.short_url = short_url
    db.session.commit()
    
    flash('URL updated successfully.', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
