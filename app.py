from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase import create_client, Client
from dotenv import load_dotenv
import os
import bcrypt
from functools import wraps

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Initialize Supabase client
supabase: Client = create_client(
    os.getenv('SUPABASE_URL'),
    os.getenv('SUPABASE_KEY')
)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            # Query user from Supabase
            response = supabase.table('users')\
                .select('*')\
                .eq('email', email)\
                .execute()
            
            if response.data and len(response.data) > 0:
                user = response.data[0]
                
                # Check password
                if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                    session['user_id'] = user['id']
                    session['user_email'] = user['email']
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid password', 'error')
            else:
                flash('Email not found', 'error')
                
        except Exception as e:
            flash(f'Login error: {str(e)}', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('login.html', show_register=True)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('login.html', show_register=True)
        
        try:
            # Hash password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Insert user into Supabase
            response = supabase.table('users').insert({
                'email': email,
                'password': hashed_password.decode('utf-8')
            }).execute()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            if 'duplicate key' in str(e).lower():
                flash('Email already registered', 'error')
            else:
                flash(f'Registration error: {str(e)}', 'error')
    
    return render_template('login.html', show_register=True)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', email=session.get('user_email'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)