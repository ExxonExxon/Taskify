from flask import Flask, redirect, url_for, render_template, session, request
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

def user_login(username, password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?, password = ?', (username, password))
    row = cursor.fetchone
    if row is not None:
        session['user'] = username
    else:
        session['allowed'] = 'Username or Password Invalid'
    

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('CREATE TABLE IF NOT EXIST users (id  INTEGER PRIMARY KEY, username TEXT, password TEXT)')

conn.commit()
conn.close()



@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        username = session.get('user')

    
    if request.method == 'POST':
        if username is not None:
            return render_template('index.html')
        else:
            return redirect(url_for(home))

@app.route('/home')
def home():
    if request.method == 'GET':
        username = session.get('username')
    if request.method == 'POST':
        if username is None:
            return redirect(url_for(index))
        else:
            user = username
            return render_template('home.html')
        
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        username = request.form.get('username')
        password = request.form.get('password')
        

    

    