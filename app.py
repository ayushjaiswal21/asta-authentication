import os
from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

# --- App Initialization ---
app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Add the 'role' column to the users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            google_id TEXT UNIQUE,
            role TEXT
        )
    ''')
    # Check if 'role' column exists before adding it to prevent errors on restart
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'role' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT")

    conn.commit()
    conn.close()

init_db()

# --- Google OAuth Configuration ---
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "YOUR_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "YOUR_CLIENT_SECRET")

google_bp = make_google_blueprint(scope=["profile", "email"])
app.register_blueprint(google_bp, url_prefix="/login")

# --- Routes ---
@app.route('/')
def index():
    """Renders the new multi-section home page."""
    user_info = session.get('google_user') or session.get('user_email')
    return render_template('index.html', user_info=user_info)

@app.route('/signin')
def signin():
    """Renders the new two-column sign-in page."""
    return render_template('signin.html')

@app.route('/join')
def join():
    """Renders the join/sign-up page."""
    return render_template('join.html')

@app.route('/forgot_password')
def forgot_password():
    """Renders the forgot password page."""
    return render_template('forgot_password.html')

@app.route('/role_selection')
def role_selection():
    """Renders the new role selection page."""
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    return render_template('role_selection.html')


@app.route('/login/google')
def login_google():
    """Redirects to Google for authentication."""
    if not google.authorized:
        return redirect(url_for("google.login"))

    try:
        resp = google.get("/oauth2/v2/userinfo")
        assert resp.ok, resp.text
        user_info = resp.json()
        google_id = user_info['id']
        email = user_info['email']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
        user = cursor.fetchone()
        
        session['google_user'] = user_info

        if not user:
            # New user, create an account
            cursor.execute("INSERT INTO users (email, google_id) VALUES (?, ?)", (email, google_id))
            conn.commit()
            cursor.execute("SELECT id FROM users WHERE google_id = ?", (google_id,))
            user_id = cursor.fetchone()[0]
            session['user_id'] = user_id
            conn.close()
            # Redirect new user to role selection
            return redirect(url_for('role_selection'))
        else:
            # Existing user
            session['user_id'] = user[0]
            conn.close()
            # If existing user has no role, send to role selection
            if not user[4]: # user[4] is the 'role' column
                return redirect(url_for('role_selection'))
            return redirect(url_for('profile'))


    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('index'))


@app.route('/join_form', methods=['POST'])
def join_form():
    """Handles the user registration form."""
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        flash("Email and password are required.", "warning")
        return redirect(url_for('join'))

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        
        # Get the new user's ID and store it in the session
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user_id = cursor.fetchone()[0]
        session['user_id'] = user_id
        session['user_email'] = email
        conn.close()

        # Redirect the new user to the role selection page
        return redirect(url_for('role_selection'))

    except sqlite3.IntegrityError:
        flash("An account with this email already exists.", "danger")
        return redirect(url_for('join'))
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('join'))


@app.route('/save_role', methods=['POST'])
def save_role():
    """Saves the user's chosen role to the database."""
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    user_id = session['user_id']
    role = request.form.get('role')

    if role in ['Seeker', 'Provider']:
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
            conn.commit()
            conn.close()
            # After saving role, redirect to the main profile/dashboard
            return redirect(url_for('profile'))
        except Exception as e:
            flash(f"Could not save your role: {e}", "danger")
            return redirect(url_for('role_selection'))
    else:
        flash("Invalid role selected.", "warning")
        return redirect(url_for('role_selection'))


@app.route('/signin_email', methods=['GET', 'POST'])
def signin_email():
    """Renders the email sign-in page and handles form submission."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Email and password are required.", "warning")
            return redirect(url_for('signin_email'))

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and user[2] and check_password_hash(user[2], password): # user[2] is password
            session['user_id'] = user[0]
            session['user_email'] = user[1]
            # If existing user has no role, send to role selection
            if not user[4]: # user[4] is the 'role' column
                return redirect(url_for('role_selection'))
            return redirect(url_for('profile'))
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for('signin_email'))

    return render_template('signin_email.html')


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.clear()
    flash("You have been successfully logged out.", "success")
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    """A protected route that shows user profile information."""
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    user_id = session['user_id']
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT email, role FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()

    if not user_data:
        return redirect(url_for('logout'))

    email, role = user_data
    return f"""
        <div style='font-family: sans-serif; text-align: center; padding: 40px;'>
            <h1>Welcome to your Profile!</h1>
            <p><strong>Email:</strong> {email}</p>
            <p><strong>Role:</strong> {role or 'Not Set'}</p>
            <br>
            <a href='/logout' style='padding: 10px 20px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 5px;'>Logout</a>
        </div>
    """


if __name__ == '__main__':
    # Make sure to run `init_db()` once when starting the app
    # if the database or table does not exist.
    init_db()
    app.run(debug=True)

