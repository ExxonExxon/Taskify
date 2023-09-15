from flask import Flask, redirect, url_for, render_template, session, request, jsonify, make_response, send_from_directory, g
from flask_session import Session
from urllib.parse import unquote
from flask_mail import Mail, Message
import os, sqlite3, random, datetime, string
from flask_bcrypt import Bcrypt
import base64
from flask_cors import CORS  # Import CORS


current_time = datetime.datetime.now()
current_hour = current_time.hour
trys = 0
cert_path = '/etc/letsencrypt/live/taskiy.ddns.net/fullchain.pem'
key_path = '/etc/letsencrypt/live/taskiy.ddns.net/privkey.pem'

app = Flask(__name__)
CORS(app)  # Initialize CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})
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
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            accountMade TEXT,
            completed_tasks NOT NULL,
            pfp TEXT NOT NULL
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
            date_made TEXT NOT NULL,
            due_date TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY,
            tasks_completed INTEGER
        )                  
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS collabs (
            id INTEGER PRIMARY KEY,
            collab_id INTEGER NOT NULL,
            collab_name TEXT NOT NULL,
            owner TEXT NOT NULL,
            user_1 TEXT,
            user_2 TEXT,
            user_3 TEXT
        )
    ''')


    db.commit()
    db.close()

init_db()

# Function to get the database connection for the current thread
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def stats_maker():
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute('INSERT OR IGNORE INTO stats (id, tasks_completed) VALUES(1, 0)')
    db.commit()
    db.close()

stats_maker()


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
    

    
def fetch_usernames(username):
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    # Query the database to retrieve usernames matching the input
    cursor.execute("SELECT username FROM users WHERE username LIKE ?", ('%' + username + '%',))
    usernames = [row[0] for row in cursor.fetchall()]

    db.close()
    return usernames



@app.route('/get_usernames')
def get_usernames():
    username = request.args.get('username')

    if not username:
        return jsonify({'usernames': []})

    usernames = fetch_usernames(username)
    return jsonify({'usernames': usernames})



@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacypolicy.html')



@app.route('/downloads')
def downloads():
    return render_template('downloads.html')



@app.route('/terms-of-services')
def tos():
    return render_template('tos.html')



@app.route('/', methods=['GET', 'POST'])
def index():
    username = request.cookies.get('user')
    if username is not None:
        return redirect(url_for('home'))
    else:
        db = get_db()
        cursor = db.cursor()

        cursor.execute('SELECT tasks_completed FROM stats')
        tasks_completed = cursor.fetchone()

        tasks_completed = int(tasks_completed[0])

        cursor.execute('SELECT * FROM users')
        users_in_db = cursor.fetchall()

        number_of_users = 0

        for users in users_in_db:
            number_of_users += 1

        cursor.close()
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
        logout_link = '/'
    elif username is None:
        groups_link = '/about'
        groups_name = 'About'
        profile_link = '/contact'
        profile_name = 'Contact'
        logout_name = 'Features'
        logout_link = '/#features'
        logout_btn_link = ''
    return render_template('updatelog.html', groups_link=groups_link, groups_name=groups_name, profile_link=profile_link, profile_name=profile_name, logout_name=logout_name, logout_link=logout_link, logout_btn_link=logout_btn_link)


@app.route('/<path:filename>')
def serve_sitemap(filename):
    return send_from_directory('static', filename)



@app.route('/contact', methods=['GET', 'POST'])
def contactus():
    if request.method == 'POST':
        email = request.form['email']
        message = request.form['message']

        msg = Message('taskiy Contact Submission',
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
    db = get_db()
    cursor = db.cursor()
    try:
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

        db.commit()
        db.close()

        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))
    


@app.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    cursor = db.cursor()
    error_message = None  # Initialize error message
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username:
            if not username or not username.strip() or not password:
                error_message = "Username and password cannot be empty."
            else:

                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                db.close()

                if not user or not bcrypt.check_password_hash(user[2], password):
                    error_message = "Invalid username or password."
                else:
                    session['user'] = user[1]
                    return redirect(url_for('home'))
    

    return render_template('login.html', error_message=error_message)



@app.route('/api/login', methods=['GET'])
def api_login():
    db = get_db()
    cursor = db.cursor()
    username = request.args.get('username')
    password = request.args.get('password')

    if username:
        if not username.strip() or not password:
            # If username or password is missing or empty, return "Not Ok"
            return jsonify({'status': 'Not Ok'}), 401
        else:

            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            db.close()

            if not user or not bcrypt.check_password_hash(user[2], password):
                # If authentication fails, return "Not Ok"
                return jsonify({'status': 'Not Ok'}), 401
            else:
                # Authentication successful, return "Ok"
                return jsonify({'status': 'Ok'}), 200

    # If there's an error or invalid request, return "Not Ok"
    return jsonify({'status': 'Not Ok'}), 401



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    db = get_db()
    cursor = db.cursor()
    error_message = ""  # Initialize the error_message variable with an empty string
    pfp = 'new_user.png'
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        tasks_completed = 0
        
        # Validate username, password, and email (your existing validation code)
        
        if not username or not username.strip() or not email or not email.strip():
            error_message = "Username and email cannot be empty."
        
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
            db.close()
            return render_template('signup.html', signed_up_users=row, error_message=error_message)
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        current_datetime = datetime.datetime.now()  # Get the current date and time
        current_date = current_datetime.date()      # Extract only the date part
        
        cursor.execute("INSERT INTO users (username, password, email, accountMade, completed_tasks, pfp) VALUES (?, ?, ?, ?, ?, ?)", (username, hashed_password, email, current_date, tasks_completed, pfp))
        db.commit()
        db.close()
        
        # Set user cookie and redirect to home (your existing code)
        
        return redirect(url_for('home'))
    
    else:
        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()
        
        row = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        
        db.close()
        
        return render_template('signup.html', signed_up_users=row, error_message=error_message)
    
@app.route('/api/signup', methods=['POST'])
def signup_api():
    db = get_db()
    cursor = db.cursor()
    data = request.get_json()  # Get JSON data from the request
    
    # Extract user data from JSON
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    # Validate username, password, and email (your existing validation code)
    if not username or not username.strip() or not email or not email.strip():
        return jsonify({"result": "not ok"}), 400
    
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        db.close()
        return jsonify({"result": "not ok"}), 400
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    existing_email = cursor.fetchone()
    
    if existing_email:
        db.close()
        return jsonify({"result": "not ok"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    current_datetime = datetime.datetime.now()  # Get the current date and time
    current_date = current_datetime.date()      # Extract only the date part
    
    cursor.execute("INSERT INTO users (username, password, email, accountMade, completed_tasks, pfp) VALUES (?, ?, ?, ?, ?, ?)",
                   (username, hashed_password, email, current_date, 0, 'new_user.png'))
    db.commit()
    db.close()
    
    # Return a success message
    return jsonify({"result": "ok"}), 200


@app.route('/home/', methods=['GET', 'POST'])
def home():
    db = get_db()
    cursor = db.cursor()
    username = request.cookies.get('user')
    wantsProfile = session.get('wantsProfile')
    if username is None:
        return redirect(url_for('index'))
    if '%20' in username:
        username = username.replace('%20', ' ')
    if '+' in username:
        username = username.replace('+', ' ')
    if wantsProfile == True:
        return redirect('/profile/')    

    session['user'] = username

    cursor.execute('SELECT pfp FROM users WHERE username = ?', (username,))
    pfp = cursor.fetchone()
    pfp = str(pfp[0])

    cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
    custom_groups = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT id, username, title, description, group_name, importance, due_date FROM tasks WHERE username = ?", (username,))
    tasks = []
    for row in cursor.fetchall():
        task = {
            'id': row[0],
            'username': row[1],
            'title': row[2],
            'description': row[3],
            'group_name': row[4],
            'importance': row[5],
            'due_date': row[6]
        }
        tasks.append(task)

    db.close()

    return render_template('home.html', username=username, custom_groups=custom_groups, tasks=tasks, pfp=pfp)

@app.route('/api/home/', methods=['GET'])
def api_home():
    db = get_db()
    cursor = db.cursor()
    # Get the username from the request query parameter
    username = request.args.get('username')
    
    # Check if the username is provided
    if not username:
        return jsonify({'status': 'Not Ok'}), 400

    try:
        # Get the path to the user's profile picture (pfp)
        pfp_path = os.path.join('static', 'pfp', f'{username}.jpg')

        # Check if the pfp file exists
        if os.path.exists(pfp_path):
            with open(pfp_path, 'rb') as pfp_file:
                # Read the pfp file as binary data
                pfp_binary = pfp_file.read()
                # Encode the binary data to Base64
                profilePicture = base64.b64encode(pfp_binary).decode('utf-8')
        else:
            profilePicture = None

        # Retrieve distinct custom group names
        cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
        custom_groups = [row[0] for row in cursor.fetchall()]

        # Retrieve tasks associated with the username
        cursor.execute("SELECT id, username, title, description, group_name, importance, due_date FROM tasks WHERE username = ?", (username,))
        tasks = []
        for row in cursor.fetchall():
            task = {
                'id': row[0],
                'username': row[1],
                'title': row[2],
                'description': row[3],
                'group_name': row[4],
                'importance': row[5],
                'due_date': row[6]
            }
            tasks.append(task)

        # Close the database connection
        db.close()

        # Create a JSON response with the retrieved data
        response_data = {
            'status': 'Ok',
            'pfp': profilePicture,
            'custom_groups': custom_groups,
            'tasks': tasks
        }

        return jsonify(response_data), 200

    except Exception as e:
        # Handle any exceptions and return an error response
        return jsonify({'status': 'Error', 'message': str(e)}), 500

@app.route('/make_collab/<string:collab_name>/<string:invited_user>/<string:owner>')
def make_collab(collab_name, invited_user, owner):
    db = get_db()
    cursor = db.cursor()
    if collab_name and invited_user and owner:
        try:
            cursor.execute('INSERT INTO collabs (collab_name, owner, user_1) VALUES (?, ?, ?)', (collab_name, owner, invited_user))
            db.commit()
            return jsonify({'status': 'OK', 'message': 'Collaboration created successfully'})
        except Exception as e:
            return jsonify({'status': 'Error', 'message': str(e)})
    else:
        return jsonify({'status': 'Error', 'message': 'Invalid input parameters'})
    
    

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
taskiy'''

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


@app.route('/upload_profile_picture', methods=['POST'])
def upload_profile_picture():
    db = get_db()
    cursor = db.cursor()
    try:
        new_username = session.get('user')
        uploaded_file = request.files['profile_picture']
        
        if uploaded_file:
            # Ensure the 'pfp' directory exists
            pfp_dir = os.path.join(app.static_folder, 'pfp')
            os.makedirs(pfp_dir, exist_ok=True)
            
            # Save the uploaded file with the username as the filename
            profile_picture_path = os.path.join(pfp_dir, f'{new_username}.jpg')
            uploaded_file.save(profile_picture_path)

            cursor.execute('UPDATE users SET pfp = ? WHERE username = ?', (f'{new_username}.jpg', new_username))
            db.commit()

            return redirect(url_for('profile'))
        else:
            return redirect(url_for('profile'))
    except Exception as e:
        error_message = str(e) if str(e) else "An error occurred"
        return redirect(url_for('profile'))

@app.route('/profile/', methods=['GET', 'POST'])
def profile():
    db = get_db()
    cursor = db.cursor()

    username = session.get('user')
    if username is None:
        session['wantsProfile'] = True
        return redirect('/login')
    message = ''
    modified_string = ''
    if request.method == 'POST':
        username = session.get('user')
        if username is None:
            session['wantsProfile'] = True
            return redirect('/login')
        if session.get('wantsPorfile') == True:
            session['wantsProfile'] = False
        existingUsername = request.form.get('existingUsername')
        newUsername = request.form.get('username')
        existingPassword = request.form.get('existingPassword')
        newPassword = request.form.get('newPassword')

        cursor.execute('SELECT pfp FROM users WHERE username = ?', (username,))
        pfp = cursor.fetchone()
        pfp = str(pfp[0])

        cursor.execute('SELECT username FROM tasks WHERE username = ?', (username,))
        tasks = cursor.fetchone()

        if existingUsername == username:
            if newUsername:
                cursor.execute('SELECT username FROM users WHERE username = ?', (newUsername,))
                existing_user = cursor.fetchone()
                print(existing_user)
                if existing_user:
                    message = 'Username already used'
                else:
                    cursor.execute('UPDATE users SET username = ? WHERE username = ?', (newUsername, existingUsername))
                    cursor.execute('UPDATE tasks SET username = ? WHERE username = ?', (newUsername, existingUsername))
                    db.commit()

                    session['user'] = newUsername
                    response = make_response(redirect(url_for('profile')))
                    response.set_cookie('user', newUsername)
                    message = f'Username has been changed to {newUsername}'
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
                db.commit()
                messagePass = 'Successfully Changed Password!'
            else:
                messagePass = 'Wrong Existing Password'
        else:
            messagePass = 'Please enter the fields. Thanks!'

        # Password Delete
        if request.form.get('deletePassword'):
            cursor.execute('UPDATE users SET password = NULL WHERE username = ?', (username,))
            db.commit()
            messagePass = 'Password deleted successfully!'


        cursor.execute('SELECT username FROM tasks WHERE username = ?', (username,))
        tasks = cursor.fetchall()

        cursor.execute('SELECT * FROM tasks WHERE title IS NULL AND description IS NULL AND username = ?', (username,))
        groups = cursor.fetchall()

        cursor.execute('SELECT accountMade FROM users WHERE username = ?', (username,))
        date_made = cursor.fetchone()

        cursor.execute('SELECT completed_tasks FROM users WHERE username = ?', (username,))
        users_completed_tasks = cursor.fetchone()
        if users_completed_tasks is not None:
            users_completed_tasks = int(users_completed_tasks[0])
        else:
            users_completed_tasks = 0  # Set a default value or handle it based on your use case


        if date_made:
            date_string = date_made[0]  # Assuming the date is the first element in the tuple
            modified_string = date_string.replace("'", "")
            modified_string = date_string.replace("-", " ")

        number_of_groups = len(groups)
        number_of_tasks = len(tasks)  # Count the number of tasks

        return render_template('profile.html', username=username, pfp=pfp, messagePass=messagePass, message=message, tasks=number_of_tasks, users_completed_tasks=users_completed_tasks, number_of_groups=number_of_groups, date_made=modified_string)
    else:
        message = None
        username = session.get('user')


        cursor.execute('SELECT pfp FROM users WHERE username = ?', (username,))
        pfp = cursor.fetchone()
        pfp = str(pfp[0])

        cursor.execute('SELECT username FROM tasks WHERE username = ?', (username,))
        tasks = cursor.fetchall()

        cursor.execute('SELECT * FROM tasks WHERE title IS NULL AND description IS NULL AND username = ?', (username,))
        groups = cursor.fetchall()

        cursor.execute('SELECT accountMade FROM users WHERE username = ?', (username,))
        date_made = cursor.fetchone()

        cursor.execute('SELECT completed_tasks FROM users WHERE username = ?', (username,))
        users_completed_tasks = cursor.fetchone()
        if users_completed_tasks is not None:
            users_completed_tasks = int(users_completed_tasks[0])
        else:
            users_completed_tasks = 0  # Set a default value or handle it based on your use case

        if date_made:
            date_string = date_made[0]  # Assuming the date is the first element in the tuple
            modified_string = date_string.replace("'", "")
            modified_string = date_string.replace("-", " ")
        
        number_of_groups = len(groups)
        number_of_tasks = len(tasks)  # Count the number of tasks

        return render_template('profile.html', username=username, pfp=pfp, tasks=number_of_tasks, number_of_groups=number_of_groups, date_made=modified_string, users_completed_tasks=users_completed_tasks)


@app.route('/reset_password/verification', methods=['GET', 'POST'])
def reset_password_verification():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        user = session.get('user')
        email = session.get('email')
        new_password = request.form.get('new_password')
        secure_num = session.get('secure_num')
        
        if secure_num is not None:
            if new_password:
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                                                                             
                cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
                db.commit()
                session['error_message'] = 'New password has been set!'
                return redirect(url_for('login'))
            else:
                return redirect(url_for('login')) 
    else:
        return render_template('reset_password_verification.html')

@app.route('/add_task', methods=['POST'])
def add_task():
    db = get_db()
    cursor = db.cursor()
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    title = request.form.get('title')
    description = request.form.get('description')
    group = request.form.get('group')
    importance = request.form.get('importance')
    due_date = request.form.get('due_date')  # Get the due date from the form

    datetime_now = datetime.datetime.now()
    date_made = datetime_now.strftime('%Y-%m-%d')  # Format the date

    # Insert task data including the due_date
    cursor.execute("INSERT INTO tasks (username, title, description, group_name, importance, date_made, due_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (username, title, description, group, importance, date_made, due_date))

    db.commit()
    db.close()

    return redirect(url_for('home'))

@app.route('/api/create/task', methods=['GET'])
def create_task():
    db = get_db()
    cursor = db.cursor()
    try:
        username = request.args.get('username')
        title = request.args.get('title')
        description = request.args.get('description')
        group = request.args.get('group')
        importance = request.args.get('importance')
        due_date = request.args.get('due_date')

        # Validate input data
        if not username or not title or not group or not importance:
            return jsonify({'status': 'Bad Request', 'message': 'Incomplete task data'}), 400

        datetime_now = datetime.datetime.now()
        date_made = datetime_now.strftime('%Y-%m-%d')  # Format the date

        # Insert task data into the database
        cursor.execute(
            "INSERT INTO tasks (username, title, description, group_name, importance, date_made, due_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, title, description, group, importance, date_made, due_date)
        )

        db.commit()
        db.close()

        # Return a success response
        response_data = {'status': 'Task Created'}
        return jsonify(response_data), 200

    except Exception as e:
        # Handle any exceptions and return an error response
        return jsonify({'status': 'Error', 'message': str(e)}), 500

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
    db = get_db()
    cursor = db.cursor()
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    group_name = request.form.get('group_name')
    if not group_name or not group_name.strip():
        error_message = "Group name cannot be empty."

        cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
        custom_groups = [row[0] for row in cursor.fetchall()]

        cursor.execute("SELECT * FROM tasks WHERE username = ?", (username,))
        tasks = [dict(id=row[0], username=row[1], title=row[2], description=row[3], group_name=row[4], importance=row[5]) for row in cursor.fetchall()]

        db.close()

    cursor.execute("SELECT group_name FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))
    existing_group = cursor.fetchone()
    if existing_group:
        db.close()
    else:
        # Assuming date_made is the name of the date field in your tasks table
        date_made = datetime.date.today()  # You may need to import datetime

        cursor.execute("INSERT INTO tasks (username, group_name, date_made) VALUES (?, ?, ?)", (username, group_name, date_made))
        db.commit()
        db.close()

    return redirect(url_for('home'))

# Create a new route for adding a group via API using GET
@app.route('/api/add_group', methods=['GET'])
def add_group_api():
    db = get_db()
    cursor = db.cursor()
    try:
        username = request.args.get('username')
        group_name = request.args.get('group_name')

        if not username or not group_name:
            return jsonify({'success': False, 'error': 'Missing username or group_name'}), 400
        # Check if the group already exists for the user
        cursor.execute("SELECT * FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))
        existing_group = cursor.fetchone()
        if existing_group:
            db.close()
            return jsonify({'success': False, 'error': 'Group already exists'}), 409

        # Assuming date_made is the name of the date field in your tasks table
        date_made = datetime.date.today()  # You may need to import datetime

        cursor.execute("INSERT INTO tasks (username, group_name, date_made) VALUES (?, ?, ?)", (username, group_name, date_made))
        db.commit()
        db.close()

        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route('/delete_group/<group_name>', methods=['POST'])
def delete_group(group_name):
    db = get_db()
    cursor = db.cursor()
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    cursor.execute("DELETE FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))

    db.commit()
    db.close()

    return redirect(url_for('home'))

@app.route('/add_group/groups', methods=['POST'])
def add_group_groups():
    db = get_db()
    cursor = db.cursor()
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    group_name = request.form.get('group_name')
    if not group_name or not group_name.strip():
        error_message = "Group name cannot be empty."

        cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
        custom_groups = [row[0] for row in cursor.fetchall()]

        cursor.execute("SELECT * FROM tasks WHERE username = ?", (username,))
        tasks = [dict(id=row[0], username=row[1], title=row[2], description=row[3], group_name=row[4], importance=row[5]) for row in cursor.fetchall()]

        db.close()

    cursor.execute("SELECT group_name FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))
    existing_group = cursor.fetchone()
    if existing_group:
        db.close()
    else:
        date_now = datetime.datetime.now()
        cursor.execute("INSERT INTO tasks (username, group_name, date_made) VALUES (?, ?, ?)", (username, group_name, date_now))
        db.commit()
        db.close()

    return redirect(url_for('groups'))

@app.route('/delete_groups/groups/<group_name>', methods=['POST'])
def delete_groups(group_name):
    db = get_db()
    cursor = db.cursor()
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    cursor.execute("DELETE FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))
    db.commit()
    db.close()

    return redirect(url_for('groups'))

@app.route('/delete_task/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    db = get_db()
    cursor = db.cursor()
    username = session.get('user')
    if username is None:
        return jsonify({'success': False, 'error': 'User not logged in'})


    cursor.execute("SELECT * FROM tasks WHERE id = ? AND username = ?", (task_id, username))
    task = cursor.fetchone()
    if not task:
        db.close()
        return jsonify({'success': False, 'error': 'Task not found'})

    cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))

    cursor.execute('SELECT tasks_completed FROM stats')
    tasks_completed = cursor.fetchone()
    tasks_completed = int(tasks_completed[0])
    tasks_completed += 1

    cursor.execute('SELECT completed_tasks FROM users WHERE username = ?', (username,))
    user_tasks_completed = cursor.fetchone()
    user_tasks_completed = int(user_tasks_completed[0])
    user_tasks_completed += 1

    cursor.execute('UPDATE stats SET tasks_completed = ?', (tasks_completed,))
    cursor.execute('UPDATE users SET completed_tasks = ? WHERE username = ?', (user_tasks_completed, username))
    db.commit()
    db.close()

    return jsonify({'success': True})

@app.route('/api/delete_task/<int:task_id>', methods=['GET'])
def delete_task_api(task_id):
    db = get_db()
    cursor = db.cursor()
    username = request.args.get('username')

    if username is None or task_id is None:
        return jsonify({'success': False, 'error': 'Missing username or task_id'})


    cursor.execute("SELECT * FROM tasks WHERE id = ? AND username = ?", (task_id, username))
    task = cursor.fetchone()
    if not task:
        db.close()
        return jsonify({'success': False, 'error': 'Task not found'})

    cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))

    cursor.execute('SELECT tasks_completed FROM stats')
    tasks_completed = cursor.fetchone()
    tasks_completed = int(tasks_completed[0])
    tasks_completed += 1

    cursor.execute('SELECT completed_tasks FROM users WHERE username = ?', (username,))
    user_tasks_completed = cursor.fetchone()
    user_tasks_completed = int(user_tasks_completed[0])
    user_tasks_completed += 1

    cursor.execute('UPDATE stats SET tasks_completed = ?', (tasks_completed,))
    cursor.execute('UPDATE users SET completed_tasks = ? WHERE username = ?', (user_tasks_completed, username))
    db.commit()
    db.close()

    return jsonify({'success': True})


@app.route('/group/<group_name>', methods=['GET'])
def group(group_name):
    db = get_db()
    cursor = db.cursor()
    username = session.get('user')
    if username is None:
        return redirect(url_for('index'))

    cursor.execute("SELECT DISTINCT group_name FROM tasks WHERE username = ?", (username,))
    custom_groups = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))
    tasks = [dict(id=row[0], username=row[1], title=row[2], description=row[3], group_name=row[4], importance=row[5]) for row in cursor.fetchall()]

    db.close()

    return render_template('group.html', username=username, custom_groups=custom_groups, tasks=tasks, selected_group=group_name)

# Create a new route for deleting groups
@app.route('/api/delete_group', methods=['GET'])
def delete_group_api():
    db = get_db()
    cursor = db.cursor()
    try:
        username = request.args.get('username')
        group_name = request.args.get('group_name')

        if not username or not group_name:
            return jsonify({'success': False, 'error': 'Missing username or group_name'}), 400

        # Check if there are tasks with the specified group_name for the user
        cursor.execute("SELECT * FROM tasks WHERE username = ? AND group_name = ?", (username, group_name))
        tasks_with_group = cursor.fetchall()
        
        if not tasks_with_group:
            db.close()
            return jsonify({'success': False, 'error': 'No tasks found with the specified group_name'}), 404

        # Delete tasks with the specified group_name and no title
        for task in tasks_with_group:
            if not task[2]:  # Assuming title is at index 2
                cursor.execute("DELETE FROM tasks WHERE id = ?", (task[0],))  # Assuming id is at index 0

        db.commit()
        db.close()

        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500



# Update your get_tasks route to include the date_created column
@app.route('/get_tasks', methods=['GET'])
def get_tasks():
    db = get_db()
    cursor = db.cursor()
    username = session.get('user')
    if username is None:
        return jsonify([])

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

    db.close()

    return jsonify(tasks)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)