from flask import Flask, redirect, url_for, render_template, session, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import random
import string
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your SMTP server address
app.config['MAIL_PORT'] = 587  # Replace with the appropriate port number
app.config['MAIL_USE_TLS'] = True  # Set to False if using SSL
app.config['MAIL_USERNAME'] = 'tomas.gorjux@gmail.com'  # Replace with your email address
app.config['MAIL_PASSWORD'] = 'tlkbnprytlecdwzn'  # Replace with your email password
bcrypt = Bcrypt(app)
mail = Mail(app)

# Database setup using SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    group_name = db.Column(db.String(100))
    importance = db.Column(db.String(20))

# Use Gevent for async support
from gevent import monkey
monkey.patch_all()

pool = None

def create_tables():
    with app.app_context():
        db.create_all()

create_tables()  # Call the function here to create the tables before any request

@app.route('/', methods=['GET', 'POST'])
def index():
    username = session.get('user')
    if request.method == 'POST':
        return redirect(url_for('home'))
    return render_template('index.html', username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not username.strip() or not password:
            error_message = "Username and password cannot be empty."
            return render_template('login.html', error_message=error_message)

        user = User.query.filter_by(username=username).first()

        if not user or not bcrypt.check_password_hash(user.password, password):
            error_message = "Invalid username or password."
            return render_template('login.html', error_message=error_message)

        # If the username and password are valid, set the user in the session
        session['user'] = user.username
        return redirect(url_for('home'))
    else:
        return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        if not username or not username.strip() or not email or not email.strip():
            error_message = "Username and email cannot be empty."
            return render_template('signup.html', error_message=error_message)

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error_message = "Username already taken. Please choose a different username."
            return render_template('signup.html', error_message=error_message)

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            error_message = "Email already registered. Please use a different email address."
            return render_template('signup.html', error_message=error_message)

        # Hash the password using Flask-Bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert the new user into the database with the hashed password
        new_user = User(username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('home'))
    else:
        return render_template('signup.html')

@app.route('/home/', methods=['GET', 'POST'])
def home():
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    custom_groups = list(set(task.group_name for task in Task.query.filter_by(username=username).all()))

    return render_template('home.html', username=username, custom_groups=custom_groups)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/reset_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        user = session.get('user')
        username = request.form.get('username')
        verification = request.form.get('verificationCode')

        if user is None:
            email = User.query.filter_by(username=username).first().email
            secure_number = random.randint(10000, 99999)
            session['secure_num'] = secure_number
            session['email'] = email

            # Send the verification email with the secure number (Code for sending email not included)

            return redirect('/check_verification')
        else:
            error_message = "Username not found. Please provide a valid username."
            return render_template('forgot_password.html', error_message=error_message)
    else:
        return render_template('forgot_password.html')

@app.route('/check_verification', methods=['GET', 'POST'])
def check_verification():
    if request.method == 'POST':
        password_length = 8  # You can adjust the length of the password here
        characters = string.ascii_letters + string.digits + string.punctuation
        new_password = ''.join(random.choice(characters) for _ in range(password_length))

        secure_number = session.get('secure_num')
        verification_field = request.form.get('verificationCode')
        if str(secure_number) in str(verification_field):
            # Get the email from the session or wherever it is stored
            email = session.get('email')

            # Send the new password to the user's email (Code for sending email not included)

            # Update the password in the database
            user = User.query.filter_by(email=email).first()
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()

            session.pop('secure_num', None)
            return redirect('/login')
        else:
            error_message = "Wrong verification code. Please retry again later!"
            return render_template('verification.html', error_message=error_message)
    else:
        return render_template('verification.html')

@app.route('/add_task', methods=['POST'])
def add_task():
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    title = request.form.get('title')
    description = request.form.get('description')
    group = request.form.get('group')
    importance = request.form.get('importance')

    new_task = Task(username=username, title=title, description=description, group_name=group, importance=importance)
    db.session.add(new_task)
    db.session.commit()

    return redirect(url_for('home'))

@app.route('/add_group', methods=['POST'])
def add_group():
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    group_name = request.form.get('group_name')
    if not group_name or not group_name.strip():
        error_message = "Group name cannot be empty."
        custom_groups = list(set(task.group_name for task in Task.query.filter_by(username=username).all()))
        return render_template('home.html', username=username, custom_groups=custom_groups, error_message=error_message)

    new_task = Task(username=username, group_name=group_name)
    db.session.add(new_task)
    db.session.commit()

    return redirect(url_for('home'))

@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    username = session.get('user')
    if username is None:
        return jsonify([])

    tasks = [
        {
            'id': row.id,
            'username': row.username,
            'title': row.title,
            'description': row.description,
            'group_name': row.group_name,
            'importance': row.importance
        }
        for row in Task.query.filter_by(username=username).all()
    ]

    return jsonify(tasks)

@app.route('/delete_task/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    username = session.get('user')
    if username is None:
        return jsonify({'success': False, 'error': 'User not logged in'})

    task = Task.query.filter_by(id=task_id, username=username).first()
    if not task:
        return jsonify({'success': False, 'error': 'Task not found'})

    db.session.delete(task)
    db.session.commit()

    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, threaded=500, debug=True,)


