from flask import Flask, redirect, url_for, render_template, session, request, jsonify, make_response, send_from_directory
from flask_session import Session
from flask_mail import Mail, Message
import os, sqlite3, random, datetime, string
from flask_bcrypt import Bcrypt

current_time = datetime.datetime.now()
current_hour = current_time.hour
trys = 0

app = Flask(__name__)
app.secret_key = 'hi'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your SMTP server address
app.config['MAIL_PORT'] = 587  # Replace with the appropriate port number
app.config['MAIL_USE_TLS'] = True  # Set to False if using SSL
app.config['MAIL_USERNAME'] = 'tomas.gorjux@gmail.com'  # Replace with your email address
app.config['MAIL_PASSWORD'] = 'tlkbnprytlecdwzn'  # Replace with your email password
bcrypt = Bcrypt(app)
mail = Mail(app)



# Database setup using SQLite
DATABASE = 'database.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            accountMade TEXT
        )
    ''')


    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            title TEXT,
            description TEXT,
            group_name TEXT NOT NULL,
            importance INTEGER,
            date_made TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY,
            tasks_completed INTEGER
        )                  
    ''')

    conn.commit()
    conn.close()

init_db()

def stats_maker():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO stats (id, tasks_completed) VALUES(1, 0)')
    conn.commit()
    conn.close()

stats_maker()

def get_db():
    db = sqlite3.connect('database.db')
    db.row_factory = sqlite3.Row
    return db

def find_task_by_id(task_id):
    try:
        connection = sqlite3.connect('database.db')  # Update with your database name
        cursor = connection.cursor()

        print("Searching for task with ID:", task_id)  # Add this line
        cursor.execute('SELECT * FROM tasks WHERE id = ?', (task_id,))
        task = cursor.fetchone()

        print("Retrieved task:", task)  # Add this line
        connection.close()

        return task
    except Exception as e:
        print(str(e))
        return None
    

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacypolicy.html')

@app.route('/terms-of-services')
def tos():
    return render_template('tos.html')

@app.route('/', methods=['GET', 'POST'])
def index():
    username = request.cookies.get('user')
    if username is not None:
        return redirect(url_for('home'))    
    else:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute('SELECT tasks_completed FROM stats')
        tasks_completed = cursor.fetchone()

        tasks_completed = int(tasks_completed[0])

        cursor.execute('SELECT * FROM users')
        users_in_db = cursor.fetchall()

        number_of_users = 0

        for users in users_in_db:
            number_of_users += 1

        return render_template('index.html', tasks_completed=tasks_completed, number_of_users=number_of_users)

@app.route('/about')
def aboutus():
    username = request.cookies.get('user')
    if username is not None:
        return redirect(url_for('home'))
    else:
        return render_template('aboutus.html')
    
@app.route('/updates')
def updates():
    username = request.cookies.get('user')
    if username is not None:
        groups_link = '/groups'
        groups_name = 'Groups'
        profile_link = '/profile'
        profile_name = 'Profile'
        logout_name = 'Logout'
        logout_btn_link = 'logout()'
        logout_link = ''
    elif username is None:
        groups_link = '/about'
        groups_name = 'About'
        profile_link = '/contact'
        profile_name = 'Contact'
        logout_name = 'Features'
        logout_link = '/#features'
        logout_btn_link = ''
    return render_template('updatelog.html', groups_link=groups_link, groups_name=groups_name, profile_link=profile_link, profile_name=profile_name)

@app.route('/<path:filename>')
def serve_sitemap(filename):
    return send_from_directory('static', filename)

@app.route('/contact', methods=['GET', 'POST'])
def contactus():
    if request.method == 'POST':
        email = request.form['email']
        message = request.form['message']

        msg = Message('Taskify Contact Submission',
                      sender='tomas.gorjux@gmail.com',  # Update with your email
                      recipients=['tomas.gorjux@gmail.com'])  # Update with your email
        msg.body = f'From: {email}\n\nMessage:\n{message}'
        mail.send(msg)

        mail_sent = 'Email has been sent! Thank you for your time!'

        return render_template('contactus.html', mail_sent=mail_sent)

    return render_template('contactus.html')

@app.route('/get_task/<int:task_id>', methods=['GET'])
def get_task(task_id):
    task = find_task_by_id(task_id)
    if task:
        return jsonify(task=task)
    else:
        return jsonify(error="Task not found"), 404


@app.route('/update_task/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    try:
        connection = sqlite3.connect('database.db')  # Update with your database name
        cursor = connection.cursor()

        updated_task = request.json  # Assuming you're sending JSON data

        cursor.execute('''
            UPDATE tasks
            SET title = ?, description = ?, group_name = ?, importance = ?
            WHERE id = ?
        ''', (
            updated_task['title'],
            updated_task['description'],
            updated_task['group_name'],
            updated_task['importance'],
            task_id
        ))

        connection.commit()
        connection.close()

        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None  # Initialize error message

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username:
            if not username or not username.strip() or not password:
                error_message = "Username and password cannot be empty."
            else:
                conn = sqlite3.connect(DATABASE)
                cursor = conn.cursor()

                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                conn.close()

                if not user or not bcrypt.check_password_hash(user[2], password):
                    error_message = "Invalid username or password."
                else:
                    session['user'] = user[1]
                    return redirect(url_for('home'))
    

    return render_template('login.html', error_message=error_message)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error_message = ""  # Initialize the error_message variable with an empty string

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # Validate username, password, and email (your existing validation code)
        
        if not username or not username.strip() or not email or not email.strip():
            error_message = "Username and email cannot be empty."
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            error_message = "Username already taken. Please choose a different username."
        
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_email = cursor.fetchone()
        
        if existing_email:
            error_message = "Email already registered. Please use a different email address."
        
        if error_message:
            row = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            conn.close()
            return render_template('signup.html', signed_up_users=row, error_message=error_message)
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        current_datetime = datetime.datetime.now()  # Get the current date and time
        current_date = current_datetime.date()      # Extract only the date part
        
        cursor.execute("INSERT INTO users (username, password, email, accountMade) VALUES (?, ?, ?, ?)", (username, hashed_password, email, current_date))
        conn.commit()
        conn.close()
        
        # Set user cookie and redirect to home (your existing code)
        
        return redirect(url_for('home'))
    
    else:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        row = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        
        conn.close()
        
        return render_template('signup.html', signed_up_users=row, error_message=error_message)

@app.route('/change-password', methods=['POST'])

@app.route('/home/', methods=['GET', 'POST'])
def home():
    username = request.cookies.get('user')
    if '%20' in username:
        username = username.replace('%20', ' ')
    if username is None:
        return redirect(url_for('index'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
    custom_groups = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM tasks WHERE username = ?", (username,))
    tasks = [dict(id=row[0], username=row[1], title=row[2], description=row[3], group_name=row[4], importance=row[5]) for row in cursor.fetchall()]
    conn.close()

    return render_template('home.html', username=username, custom_groups=custom_groups, tasks=tasks)

@app.route('/groups/', methods=['GET', 'POST'])
def groups():
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    if request.method == 'POST':
        new_group_name = request.form.get('new_group_name')

        cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
        existing_groups = [row[0] for row in cursor.fetchall()]

        if new_group_name in existing_groups:
            conn.close()
            return render_template('groups.html', username=username, custom_groups=existing_groups, tasks=tasks, error='Group already exists.')

        cursor.execute("INSERT INTO tasks (username, group_name) VALUES (?, ?)", (username, new_group_name))
        conn.commit()

    cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
    custom_groups = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM tasks WHERE username = ?", (username,))
    tasks = [dict(id=row[0], username=row[1], title=row[2], description=row[3], group_name=row[4], importance=row[5]) for row in cursor.fetchall()]

    conn.close()

    return render_template('groups.html', username=username, custom_groups=custom_groups, tasks=tasks)

@app.route('/reset_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        user = session.get('user')
        email = request.form.get('email')
        verification = request.form.get('verificationCode')

        if user is None or user is not None:
            secure_number = random.randint(10000, 99999)
            session['secure_num'] = secure_number
            session['email'] = email

            msg = Message(subject='Reset Password Verification Code',
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[email])
            msg.body = f'''Password Reset Request Received
-------------------------------------------------

We have received a request to reset your password. To proceed with the password reset process, please use the following verification code:

Verification Code: {secure_number}

If you did not initiate this request, you can safely ignore this message. Your account security is important to us.

Thank you,
Taskify'''

            mail.send(msg)     
            return redirect(url_for('check_code'))
    else:
        return render_template('forgot_password.html')
    
@app.route('/check_verification_code', methods=['GET', 'POST'])
def check_code():
    global trys

    if request.method == 'POST':
        user = session.get('user')
        code = request.form.get('verificationCode')
        secure_num = session.get('secure_num')

        if user is None or user is not None:
            if code == str(secure_num):  # Convert secure_num to string for comparison
                secure_num = random.randint(0, 9994539423423)
                session['secure_num'] = secure_num
                trys = 0
                return redirect(url_for('reset_password_verification'))
            else:
                trys += 1
                attempts = 10 - trys

                if trys >= 10:
                    error_message = 'Your verification code entry has been unsuccessful after 10 attempts. For security reasons, please wait a while before trying again. Thank you for your patience.'
                    session['error_message'] = error_message
                    return redirect(url_for('login'))
                else:
                    stats = f'Incorrect verification code. Please try again. You have {attempts} left'
                    return render_template('verification_code_check.html', stats=stats)
        else:
            # Redirect to the login page if user is not logged in
            return redirect(url_for('login'))
    else:
        return render_template('verification_code_check.html')

@app.route('/pricing-pro', methods=['GET', 'POST'])
def pricing_pro():
    return render_template('pricing_pro.html')

@app.route('/profile/', methods=['GET', 'POST'])
def profile():
    message = ''
    if request.method == 'POST':
        username = request.cookies.get('user')
        existingUsername = request.form.get('existingUsername')
        newUsername = request.form.get('username')
        existingPassword = request.form.get('existingPassword')
        newPassword = request.form.get('newPassword')
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute('SELECT username FROM tasks WHERE username = ?', (username,))
        tasks = cursor.fetchone()

        if existingUsername:
            if existingUsername == username:
                if newUsername:
                    cursor.execute('UPDATE users SET username = ? WHERE username = ?', (newUsername, existingUsername))
                    cursor.execute('UPDATE tasks SET username = ? WHERE username = ?', (newUsername, existingUsername))
                    conn.commit()

                    # Update the session and cookie with the new username
                    session['user'] = newUsername
                    response = make_response(redirect(url_for('profile')))
                    response.set_cookie('user', newUsername)

                    return response
                else:
                    message = 'Please enter your new username!'
            else:
                message = 'That is not your current username!'


        if existingPassword and newPassword:
            cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
            passwordNow = cursor.fetchone()

            if passwordNow and bcrypt.check_password_hash(passwordNow[0], existingPassword):
                hashed_new_password = bcrypt.generate_password_hash(newPassword).decode('utf-8')
                cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_new_password, username))
                conn.commit()
                messagePass = 'Successfully Changed Password!'
            else:
                messagePass = 'Wrong Existing Password'
        else:
            messagePass = 'Please enter the fields. Thanks!'

        # Password Delete
        if request.form.get('deletePassword'):
            cursor.execute('UPDATE users SET password = NULL WHERE username = ?', (username,))
            conn.commit()
            messagePass = 'Password deleted successfully!'
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute('SELECT username FROM tasks WHERE username = ?', (username,))
        tasks = cursor.fetchall()

        cursor.execute('SELECT * FROM tasks WHERE title IS NULL AND description IS NULL AND username = ?', (username,))
        groups = cursor.fetchall()

        cursor.execute('SELECT accountMade FROM users WHERE username = ?', (username,))
        date_made = cursor.fetchone()

        if date_made:
            date_string = date_made[0]  # Assuming the date is the first element in the tuple
            modified_string = date_string.replace("'", "")
            modified_string = date_string.replace("-", " ")

        number_of_groups = len(groups)
        number_of_tasks = len(tasks)  # Count the number of tasks

        return render_template('profile.html', username=username, messagePass=messagePass, message=message, tasks=number_of_tasks, number_of_groups=number_of_groups, date_made=modified_string)
    else:
        message = None
        username = session.get('user')
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute('SELECT username FROM tasks WHERE username = ?', (username,))
        tasks = cursor.fetchall()

        cursor.execute('SELECT * FROM tasks WHERE title IS NULL AND description IS NULL AND username = ?', (username,))
        groups = cursor.fetchall()

        cursor.execute('SELECT accountMade FROM users WHERE username = ?', (username,))
        date_made = cursor.fetchone()

        if date_made:
            date_string = date_made[0]  # Assuming the date is the first element in the tuple
            modified_string = date_string.replace("'", "")
            modified_string = date_string.replace("-", " ")
        
        number_of_groups = len(groups)
        number_of_tasks = len(tasks)  # Count the number of tasks

        return render_template('profile.html', username=username, tasks=number_of_tasks, number_of_groups=number_of_groups, date_made=modified_string)


@app.route('/reset_password/verification', methods=['GET', 'POST'])
def reset_password_verification():
    if request.method == 'POST':
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        user = session.get('user')
        email = session.get('email')
        new_password = request.form.get('new_password')
        secure_num = session.get('secure_num')
        
        if secure_num is not None:
            if new_password:
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                                                                             
                cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
                conn.commit()
                session['error_message'] = 'New password has been set!'
                return redirect(url_for('login'))
            else:
                return redirect(url_for('login')) 
    else:
        return render_template('reset_password_verification.html')

@app.route('/add_task', methods=['POST'])
def add_task():
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    title = request.form.get('title')
    description = request.form.get('description')
    group = request.form.get('group')
    importance = request.form.get('importance')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    datetime_now = datetime.datetime.now()
    date_made = datetime_now.date()

    cursor.execute("INSERT INTO tasks (username, title, description, group_name, importance, date_made) VALUES (?, ?, ?, ?, ?, ?)",
                   (username, title, description, group, importance, date_made))
    conn.commit()
    conn.close()

    return redirect(url_for('home'))

# Establish a connection to your SQLite database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Your database creation queries here (users and tasks tables)

@app.route('/delete-account', methods=['POST'])
def delete_account():
    if request.method == 'POST':
        password_to_verify = request.form['verify_password']  # Change to 'verify_password'

        # Establish a new database connection and cursor
        db = get_db()
        cursor = db.cursor()

        username = request.cookies.get('user')
        if '%20' in username:
            username = username.replace('%20', ' ')
            

        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result and bcrypt.check_password_hash(result['password'], password_to_verify):  # Use bcrypt to check password
            cursor.execute("DELETE FROM users WHERE username = ?", (username,))
            cursor.execute("DELETE FROM tasks WHERE username = ?", (username,))
            db.commit()

            response = redirect('/')
            
            # Delete the cookies by setting them to an empty value and setting an expired date
            response.delete_cookie('user')
            response.delete_cookie('dark_mode')

            return response

        else:
            return "Invalid password. Please double-check and try again. Go <a href='/profile/'>Home</a>"

    return render_template('delete_account.html')


@app.route('/add_group', methods=['POST'])
def add_group():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    group_name = request.form.get('group_name')
    if not group_name or not group_name.strip():
        error_message = "Group name cannot be empty."
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
        custom_groups = [row[0] for row in cursor.fetchall()]

        cursor.execute("SELECT * FROM tasks WHERE username = ?", (username,))
        tasks = [dict(id=row[0], username=row[1], title=row[2], description=row[3], group_name=row[4], importance=row[5]) for row in cursor.fetchall()]

        conn.close()

    cursor.execute("SELECT group_name FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))
    existing_group = cursor.fetchone()
    if existing_group:
        conn.close()
    else:
        # Assuming date_made is the name of the date field in your tasks table
        date_made = datetime.date.today()  # You may need to import datetime

        cursor.execute("INSERT INTO tasks (username, group_name, date_made) VALUES (?, ?, ?)", (username, group_name, date_made))
        conn.commit()
        conn.close()

    return redirect(url_for('home'))

@app.route('/delete_group/<group_name>', methods=['POST'])
def delete_group(group_name):
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))

    conn.commit()
    conn.close()

    return redirect(url_for('home'))

@app.route('/add_group/groups', methods=['POST'])
def add_group_groups():
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    group_name = request.form.get('group_name')
    if not group_name or not group_name.strip():
        error_message = "Group name cannot be empty."
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
        custom_groups = [row[0] for row in cursor.fetchall()]

        cursor.execute("SELECT * FROM tasks WHERE username = ?", (username,))
        tasks = [dict(id=row[0], username=row[1], title=row[2], description=row[3], group_name=row[4], importance=row[5]) for row in cursor.fetchall()]

        conn.close()

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT group_name FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))
    existing_group = cursor.fetchone()
    if existing_group:
        conn.close()
    else:
        date_now = datetime.datetime.now()
        cursor.execute("INSERT INTO tasks (username, group_name, date_made) VALUES (?, ?, ?)", (username, group_name, date_now))
        conn.commit()
        conn.close()

    return redirect(url_for('groups'))

@app.route('/delete_groups/groups/<group_name>', methods=['POST'])
def delete_groups(group_name):
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))
    conn.commit()
    conn.close()

    return redirect(url_for('groups'))

@app.route('/delete_task/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    username = session.get('user')
    if username is None:
        return jsonify({'success': False, 'error': 'User not logged in'})

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM tasks WHERE id = ? AND username = ?", (task_id, username))
    task = cursor.fetchone()
    if not task:
        conn.close()
        return jsonify({'success': False, 'error': 'Task not found'})

    cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))

    cursor.execute('SELECT tasks_completed FROM stats')
    tasks_completed = cursor.fetchone()
    tasks_completed = int(tasks_completed[0])
    tasks_completed += 1

    cursor.execute('UPDATE stats SET tasks_completed = ?', (tasks_completed,))
    conn.commit()
    conn.close()

    return jsonify({'success': True})

@app.route('/group/<group_name>', methods=['GET'])
def group(group_name):
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
    custom_groups = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))
    tasks = [dict(id=row[0], username=row[1], title=row[2], description=row[3], group_name=row[4], importance=row[5]) for row in cursor.fetchall()]

    conn.close()

    return render_template('group.html', username=username, custom_groups=custom_groups, tasks=tasks, selected_group=group_name)


# Update your get_tasks route to include the date_created column
@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    username = session.get('user')
    if username is None:
        return jsonify([])

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT id, username, title, description, group_name, importance, date_made FROM tasks WHERE username = ?", (username,))
    tasks = [
        {
            'id': row[0],
            'username': row[1],
            'title': row[2],
            'description': row[3],
            'group_name': row[4],
            'importance': row[5],
            'date_made': row[6]
        }
        for row in cursor.fetchall()
    ]

    conn.close()

    return jsonify(tasks)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, threaded=True, debug=True)
