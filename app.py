from flask import Flask, redirect, url_for, render_template, session, request, jsonify
import sqlite3
from flask_mail import Mail, Message
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your SMTP server address
app.config['MAIL_PORT'] = 587  # Replace with the appropriate port number
app.config['MAIL_USE_TLS'] = True  # Set to False if using SSL
app.config['MAIL_USERNAME'] = 'tomas.gorjux@gmail.com'  # Replace with your email address
app.config['MAIL_PASSWORD'] = 'tlkbnprytlecdwzn'  # Replace with your email password

mail = Mail(app)


conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, email TEXT NOT NULL)')
cursor.execute('CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, username TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, group_name TEXT, importance TEXT)')
conn.commit()
conn.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    username = session.get('user')
    if request.method == 'POST':
        return redirect(url_for('home'))
    return render_template('index.html', username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        username = request.form.get('username')
        password = request.form.get('password')
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        row = cursor.fetchone()
        conn.close()
        if row is not None:
            session['user'] = username
            return redirect('/home/')
        else:
            session['allowed'] = 'Username or Password Invalid'

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user = session.get('user')
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        # Check if username is provided and not an empty string
        if username and username.strip():
            cursor.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, password, email))
            conn.commit()
            conn.close()
            return redirect(url_for('home'))
        else:
            error_message = "Username cannot be empty."
            return render_template('signup.html', error_message=error_message)
    else:
        return render_template('signup.html')
    
@app.route('/home/', methods=['GET', 'POST'])
def home():
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT group_name FROM tasks WHERE username = ?', (username,))
    custom_groups = [row[0] for row in cursor.fetchall()]
    conn.close()

    return render_template('home.html', username=username, custom_groups=custom_groups)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/reset_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        user = session.get('user')
        username = request.form.get('username')
        verification = request.form.get('verificationCode')

        print("User:", user)
        print("Username:", username)
        print("Verification Code:", verification)

        if user is None:
            cursor.execute('SELECT email FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if result:
                email = result[0]  # Extract the email from the tuple
                secure_number = random.randint(10000, 99999)
                session['secure_num'] = secure_number
                secure_number = session.get('secure_num')
                print("Secure Number:", secure_number)
                msg = Message(f'Security Number Taskify: {secure_number}',
                              sender='your_gmail_username@gmail.com',
                              recipients=[email])  # Ensure email is taken from the tuple
                msg.body = f"""To verify your identity for Taskify, please enter the following 5-digit security number on the website:

                            Security Number: {secure_number}

                            Please do not share this security number with anyone else. It is used to ensure that you are the authorized user of this account.

                            If you did not request this verification, please disregard this message. Thank you for using Taskify!"""
                mail.send(msg)
                allowed = "Success! An email has been sent to the email address provided during signup. Please check your inbox for further instructions on how to proceed with the account recovery process. If you don't receive an email within a few minutes, please check your spam folder, and ensure that you provided the correct email address during signup."
            else:
                allowed = "Username not found. Please provide a valid username."
            
            print("Allowed:", allowed)  # Check the value of 'allowed' variable
            return render_template('forgot_password.html', allowed=allowed)
    else:
        return render_template('forgot_password.html')
    
@app.route('/check_verification', methods=['GET', 'POST'])
def check_verification():
    if request.method == 'GET':
        newPassword = random.randint(10001, 99997)
        secure_number = session.get('secure_num')
        verification_field = request.form.get('verificationCode')
        if secure_number == verification_field:
            msg = Message(f'New Password Taskify: {newPassword}',
                                  sender='your_gmail_username@gmail.com',
                                  recipients=[email])  # Ensure email is taken from the tuple
            msg.body = f"""Your password has been changed to the following:

                        
                        New Password: {newPassword}

                        Please do not share this password with anyone. This is supposed to be temporary and not to be used forever, so change it ASAP.

                        Thank you for using Taskify!"""
            mail.send(msg)
            allowed = "Success! Your password has been changed! Make sure to change it after!"



@app.route('/add_task', methods=['POST'])
def add_task():
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    title = request.form.get('title')
    description = request.form.get('description')
    group = request.form.get('group')
    importance = request.form.get('importance')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO tasks (username, title, description, group_name, importance) VALUES (?, ?, ?, ?, ?)',
                   (username, title, description, group, importance))
    conn.commit()
    conn.close()

    return redirect(url_for('home'))

@app.route('/add_group', methods=['POST'])
def add_group():
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    group_name = request.form.get('group_name')
    if not group_name or not group_name.strip():
        error_message = "Group name cannot be empty."
        return render_template('home.html', username=username, custom_groups=get_custom_groups(username),
                               error_message=error_message)

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO tasks (username, group_name) VALUES (?, ?)', (username, group_name))
    conn.commit()
    conn.close()

    return redirect(url_for('home'))

@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    username = session.get('user')
    if username is None:
        return jsonify([])

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tasks WHERE username = ?', (username,))
    tasks = [
        {
            'id': row[0],
            'username': row[1],
            'title': row[2],
            'description': row[3],
            'group_name': row[4],
            'importance': row[5]
        }
        for row in cursor.fetchall()
    ]
    conn.close()

    return jsonify(tasks)

# New route to delete a task from the database
@app.route('/delete_task/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    username = session.get('user')
    if username is None:
        return jsonify({'success': False, 'error': 'User not logged in'})

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM tasks WHERE id = ? AND username = ?', (task_id, username))
    conn.commit()
    conn.close()

    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=True)
