from flask import Flask, request, redirect, session
import hashlib
import re
import time

app = Flask(__name__)
app.secret_key = "secret123"

# ---------------- LIGHT UI STYLE ----------------
STYLE = """
<style>
body {
    margin: 0;
    height: 100vh;
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #f4f6f8;
    display: flex;
    justify-content: center;
    align-items: center;
}

.card {
    background: white;
    padding: 28px;
    border-radius: 10px;
    width: 340px;
    box-shadow: 0 8px 20px rgba(0,0,0,0.08);
    text-align: center;
}

h2 {
    margin-bottom: 18px;
    color: #333;
}

input {
    width: 100%;
    padding: 10px;
    margin-top: 10px;
    border-radius: 6px;
    border: 1px solid #ddd;
    outline: none;
}

input:focus {
    border-color: #6c63ff;
}

button {
    width: 100%;
    padding: 10px;
    margin-top: 15px;
    border: none;
    border-radius: 6px;
    background: #6c63ff;
    color: white;
    font-weight: 600;
    cursor: pointer;
}

button:hover {
    background: #5a54e6;
}

a {
    display: block;
    margin-top: 14px;
    color: #6c63ff;
    text-decoration: none;
    font-size: 14px;
}

.rules {
    text-align: left;
    margin-top: 12px;
    font-size: 13px;
    line-height: 1.6;
}

.rules p {
    margin: 3px 0;
    color: #c62828;
    transition: 0.2s;
}
</style>
"""

# ---------------- DATA ----------------
users = {
    "admin": {
        "password": hashlib.sha256("Admin@123".encode()).hexdigest(),
        "role": "admin"
    }
}

messages = []

login_attempts = {}
LOCK_TIME = 300
MAX_ATTEMPTS = 3

request_times = {}
RATE_LIMIT = 10
WINDOW = 60

# ---------------- HELPERS ----------------
def sanitize(text):
    return text.replace("<", "&lt;").replace(">", "&gt;")

def valid_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

# ---------------- LOGIN PAGE ----------------
@app.route('/')
def home():
    return f'''
    <body>
    <div class="card">
        <h2>Login</h2>

        <form action="/login" method="post">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>

        <a href="/register">Create Account</a>
    </div>
    {STYLE}
    </body>
    '''

# ---------------- LOGIN ----------------
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    now = time.time()

    ip = request.remote_addr

    if ip not in request_times:
        request_times[ip] = []

    request_times[ip] = [t for t in request_times[ip] if now - t < WINDOW]

    if len(request_times[ip]) >= RATE_LIMIT:
        return "Too many requests"

    request_times[ip].append(now)

    if username not in login_attempts:
        login_attempts[username] = {"count": 0, "lock_until": 0}

    user_data = login_attempts[username]

    if now < user_data["lock_until"]:
        return "Account locked for 5 minutes"

    hashed = hashlib.sha256(password.encode()).hexdigest()

    if username in users and users[username]["password"] == hashed:
        session['user'] = username
        session['role'] = users[username]['role']
        login_attempts[username] = {"count": 0, "lock_until": 0}
        return redirect('/dashboard')

    user_data["count"] += 1

    if user_data["count"] >= MAX_ATTEMPTS:
        user_data["lock_until"] = now + LOCK_TIME
        user_data["count"] = 0
        return "Too many attempts. Locked for 5 minutes"

    return f"Login Failed ({user_data['count']}/3)"

# ---------------- REGISTER PAGE ----------------
@app.route('/register')
def register():
    return f'''
    <body>

    <div class="card">
        <h2>Create Account</h2>

        <form action="/register" method="post">
            <input name="username" placeholder="Username" required>

            <input id="password" name="password" type="password"
            placeholder="Password" required onkeyup="checkPassword()">

            <div class="rules">
                <p id="len">At least 8 characters</p>
                <p id="upper">One uppercase letter (A-Z)</p>
                <p id="lower">One lowercase letter (a-z)</p>
                <p id="num">One number (0-9)</p>
                <p id="sym">One special symbol (!@#$%^&*)</p>
            </div>

            <button type="submit">Register</button>
        </form>

        <a href="/">Back to Login</a>
    </div>

    <script>
    function checkPassword() {{
        let p = document.getElementById("password").value;

        setRule("len", p.length >= 8);
        setRule("upper", /[A-Z]/.test(p));
        setRule("lower", /[a-z]/.test(p));
        setRule("num", /[0-9]/.test(p));
        setRule("sym", /[!@#$%^&*]/.test(p));
    }}

    function setRule(id, valid) {{
        let el = document.getElementById(id);
        el.style.color = valid ? "#2e7d32" : "#c62828";
    }}
    </script>

    {STYLE}
    </body>
    '''

# ---------------- REGISTER ----------------
@app.route('/register', methods=['POST'])
def register_user():
    username = request.form['username']
    password = request.form['password']

    if len(username) < 3:
        return "Username too short"

    if not valid_password(password):
        return "Weak password"

    if username in users:
        return "User exists"

    users[username] = {
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "role": "user"
    }

    return redirect('/')

# ---------------- DASHBOARD ----------------
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect('/')

    if request.method == 'POST':
        msg = sanitize(request.form['msg'])
        messages.append({"user": session['user'], "text": msg})

    content = ""

    # ---------------- ADMIN VIEW ----------------
    if session['role'] == 'admin':
        content += "<h3>User Table (Hashed Passwords)</h3>"
        content += """
        <table border="1" cellpadding="5" cellspacing="0">
            <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Password Hash (SHA-256)</th>
            </tr>
        """

        for u in users:
            content += f"""
            <tr>
                <td>{u}</td>
                <td>{users[u]['role']}</td>
                <td>{users[u]['password']}</td>
            </tr>
            """

        content += "</table><br><br>"

        content += "<h3>All Messages</h3>"
        for m in messages:
            content += f"{m['user']} : {m['text']}<br>"

    # ---------------- USER VIEW ----------------
    else:
        for m in messages:
            if m['user'] == session['user']:
                content += f"{m['text']}<br>"

    return f'''
    <body>
    <div class="card" style="width:400px;">
        <h2>Dashboard</h2>

        <p><b>User:</b> {session['user']}</p>
        <p><b>Role:</b> {session['role']}</p>

        <form method="post">
            <input name="msg" placeholder="Enter message" required>
            <button type="submit">Add</button>
        </form>

        <div style="margin-top:15px; text-align:left; max-height:150px; overflow:auto;">
            {content}
        </div>

        <a href="/logout">Logout</a>
    </div>

    {STYLE}
    </body>
    '''

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

app.run(debug=True)