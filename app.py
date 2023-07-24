from flask import Flask, redirect, url_for, render_template, session, request
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, email TEXT NOT NULL)')
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
            return redirect(url_for('home'))
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
    
@app.route('/home', methods=['GET', 'POST'])
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


if __name__ == '__main__':
    app.run(debug=True)
