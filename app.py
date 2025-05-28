from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file , current_app
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
import sqlite3
import os
import uuid
import magic  
from datetime import datetime, timedelta
import pytz
from functools import wraps
from PyPDF2 import PdfMerger
from apscheduler.schedulers.background import BackgroundScheduler  # Added missing import
from werkzeug.utils import safe_join


app = Flask(__name__)
app.secret_key = 'Muhammed_morad@photo_marget&2003'

# Initialize Flask-Login

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Specify login view for redirects


app.config['PDF_UPLOAD_FOLDER'] = 'static/uploads/pdf'
app.config['PDF_MERGE_FOLDER'] = 'static/merged/pdf'

merge_folder = app.config['PDF_MERGE_FOLDER']
if not os.path.exists(merge_folder):
    os.makedirs(merge_folder, exist_ok=True)


os.makedirs(app.config['PDF_UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PDF_MERGE_FOLDER'], exist_ok=True)

# Database initialization
def init_db():
    # Ensure database directory exists
    os.makedirs('database', exist_ok=True)
    
    # Users database
    with sqlite3.connect('database/users.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            username TEXT UNIQUE,
            password TEXT,
            is_active BOOLEAN DEFAULT 1,
            is_admin BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Create initial admin user
        admin_exists = conn.execute('SELECT 1 FROM users WHERE username = "System"').fetchone()
        if not admin_exists:
            conn.execute('''INSERT INTO users 
                (name, username, password, is_admin) 
                VALUES (?, ?, ?, ?)''',
                ('Administrator', 'System', generate_password_hash('admin2030'), 1)
            )

    # Logs database
    with sqlite3.connect('database/logs.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')

    # Operations database: logs table
    with sqlite3.connect('database/operation.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            description TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')


init_db()

# User class
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data[0]
        self.name = user_data[1]
        self.username = user_data[2]
        self._is_active = bool(user_data[4])
        self._is_admin = bool(user_data[5])

    @property
    def is_active(self):
        return self._is_active
    
    @is_active.setter
    def is_active(self, value):
        self._is_active = value
        
    @property
    def is_admin(self):
        return self._is_admin

# log_action
def log_action(user_id, action, description):
    conn = sqlite3.connect('database/operation.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (user_id, action, description)
        VALUES (?, ?, ?)
    ''', (user_id, action, description))
    conn.commit()
    conn.close()

@app.errorhandler(401)
def unauthorized_error(error):
    return render_template('401.html'), 401

# User loader
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database/users.db')
    user_data = conn.execute('''
        SELECT id, name, username, password, is_active, is_admin 
        FROM users 
        WHERE id = ?
    ''', (user_id,)).fetchone()
    conn.close()
    return User(user_data) if user_data else None

# Activity logger
def log_activity(username, action):
    cairo_tz = pytz.timezone('Africa/Cairo')
    timestamp = datetime.now(cairo_tz).strftime('%Y-%m-%d %H:%M:%S')
    
    with sqlite3.connect('database/logs.db') as conn:
        conn.execute("INSERT INTO logs (username, action, timestamp) VALUES (?, ?, ?)",
                    (username, action, timestamp))

# Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Unauthorized access!', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database/users.db')
        user_data = conn.execute('''
            SELECT id, name, username, password, is_active, is_admin 
            FROM users 
            WHERE username = ?
        ''', (username,)).fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[3], password):
            if not user_data[4]:
                flash('Account is deactivated', 'danger')
                return redirect(url_for('login'))
            
            user = User(user_data)
            login_user(user)
            log_activity(user.username, 'Login')
            
            # Check if 'next' parameter exists for proper redirection
            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin_panel' if user.is_admin else 'home'))
        
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

# Fixed redundant log_activity definition
@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.username, 'Logout')
    logout_user()
    return redirect(url_for('login'))


# User management routes
@app.route('/admin/user_activation', methods=['GET', 'POST'])
@login_required
@admin_required
def user_activation():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        try:
            conn = sqlite3.connect('database/users.db')
            cursor = conn.cursor()
            
            # Prevent self-deactivation
            if int(user_id) == current_user.id:
                flash("Cannot modify your own status!", 'warning')
                return redirect(url_for('user_activation'))
            
            # Toggle status
            cursor.execute('SELECT is_active FROM users WHERE id = ?', (user_id,))
            current_status = cursor.fetchone()[0]
            new_status = 0 if current_status else 1
            
            # Update database
            cursor.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, user_id))
            conn.commit()
            
            action = 'activated' if new_status else 'deactivated'
            flash(f'User {action} successfully', 'success')
            
        except Exception as e:
            conn.rollback()
            flash(f'Error: {str(e)}', 'danger')
        finally:
            conn.close()
    
    # Get all users
    conn = sqlite3.connect('database/users.db')
    users = conn.execute('''
        SELECT id, name, username, is_active, is_admin 
        FROM users
    ''').fetchall()
    conn.close()
    
    return render_template('user_activation.html', users=users)


# Update navigation menu in templates
def is_admin(user_id):
    conn = sqlite3.connect('database/users.db')
    user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user and user[0] == 1

# Admin Panel
@app.route('/admin/panel')
@login_required
@admin_required  # Added admin_required decorator for consistency
def admin_panel():
    return render_template('admin.html') 

# Show Users
@app.route('/admin/users')
@login_required
@admin_required  # Added admin_required decorator
def manage_users():
    conn = sqlite3.connect('database/users.db')
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

# Create User
@app.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
@admin_required  # Added admin_required decorator
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        name = request.form['name']
        is_admin_flag = int(request.form.get('is_admin', 0))  # 0 or 1 checkbox
        is_active_flag = int(request.form.get('is_active', 0))  # default active

        try:
            conn = sqlite3.connect('database/users.db')
            conn.execute('''INSERT INTO users (name, username, password, is_active, is_admin)
                            VALUES (?, ?, ?, ?, ?)''',
                        (name, username, password, is_active_flag, is_admin_flag))
            conn.commit()
            log_action(current_user.id, 'CREATE_USER', f'Created user {username}')
            flash('User created successfully', 'success')
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        finally:
            conn.close()
        
        return redirect(url_for('manage_users'))
    
    return render_template('create_user.html')


# Update User (fixed typo in comment)
@app.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required  # Added admin_required decorator
def edit_user(user_id):
    conn = sqlite3.connect('database/users.db')
    conn.row_factory = sqlite3.Row 
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        is_admin_flag = int(request.form.get('is_admin', 0))
        is_active_flag = int(request.form.get('is_active', 0))
        new_password = request.form.get('password')

        changes = []
        if user['name'] != name:
            changes.append(f"Name: '{user['name']}' → '{name}'")
        if user['username'] != username:
            changes.append(f"Username: '{user['username']}' → '{username}'")
        if user['is_admin'] != is_admin_flag:
            changes.append(f"Is Admin: {user['is_admin']} → {is_admin_flag}")
        if user['is_active'] != is_active_flag:
            changes.append(f"Is Active: {user['is_active']} → {is_active_flag}")
        if new_password:
            changes.append("Password: [CHANGED]")


        update_query = 'UPDATE users SET name = ?, username = ?, is_admin = ?, is_active = ?'
        params = [name, username, is_admin_flag, is_active_flag]

        if new_password:
            update_query += ', password = ?'
            params.append(generate_password_hash(new_password))

        update_query += ' WHERE id = ?'
        params.append(user_id)

        conn.execute(update_query, params)
        conn.commit()
        conn.close()
        flash('User updated successfully', 'success')

        description = f"Updated user {user['username']}. Changes: " + '; '.join(changes) if changes else "No changes made"
        log_action(current_user.id, 'UPDATE_USER', description)

        return redirect(url_for('manage_users'))

    conn.close()
    return render_template('edit_user.html', user=user)


# delete user
@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required  # Added admin_required decorator
def delete_user(user_id):
    # Prevent self-deletion
    if user_id == current_user.id:
        flash("Cannot delete your own account!", 'warning')
        return redirect(url_for('manage_users'))
        
    conn = sqlite3.connect('database/users.db')
    cursor = conn.cursor()

    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()

    if result:
        username = result[0]
        
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        
        log_action(current_user.id, 'DELETE_USER', f'Deleted user {username}')
        flash('User deleted successfully', 'success')
    else:
        flash('User not found', 'danger')

    conn.close()
    return redirect(url_for('manage_users'))

# Show log
@app.route('/admin/logs')
@login_required
@admin_required  # Added admin_required decorator
def view_logs():
    conn = sqlite3.connect('database/logs.db')
    logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC').fetchall()
    conn.close()
    return render_template('admin_logs.html', logs=logs)

# view_operation
@app.route('/admin/operation')
@login_required
@admin_required  # Added admin_required decorator
def view_operation():
    conn = sqlite3.connect('database/operation.db')
    conn.row_factory = sqlite3.Row

    conn.execute("ATTACH DATABASE 'database/users.db' AS users_db")

    query = '''
        SELECT logs.id, logs.user_id, logs.action, logs.description, logs.timestamp, users_db.users.name AS username
        FROM logs
        LEFT JOIN users_db.users ON logs.user_id = users_db.users.id
        ORDER BY logs.timestamp DESC
    '''
    operation = conn.execute(query).fetchall()
    conn.close()

    return render_template('admin_operation.html', operation=operation)


# Index Page
@app.route('/')
def index():
    return render_template('index.html')


# Home
@app.route('/home')
@login_required
def home():
    # Get actual stats from database rather than hardcoded values
    conn = sqlite3.connect('database/operation.db')
    cursor = conn.cursor()
    
    # Get user-specific file count
    cursor.execute('''
        SELECT COUNT(*) FROM operations 
        WHERE user = ? AND action IN ('UPLOAD_IMAGE', 'UPLOAD_PDF')
    ''', (current_user.username,))
    user_files = cursor.fetchone()[0] or 0
    
    # Get merged file count
    cursor.execute('''
        SELECT COUNT(*) FROM operations 
        WHERE user = ? AND action IN ('MERGE_IMAGE', 'MERGE_PDF')
    ''', (current_user.username,))
    merged_files = cursor.fetchone()[0] or 0
    
    conn.close()
    
    stats = {
        'user_files': user_files,
        'merged_files': merged_files,
        'remaining_time': 30  # Placeholder value
    }
    return render_template('home.html', **stats)


def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in allowed_extensions

def allowed_file(file, filename, filetype):
    # Check extension
    ext_ok = '.' in filename and filename.rsplit('.', 1)[1].lower() == filetype
    if not ext_ok:
        return False

    # Check MIME type
    mime = magic.Magic(mime=True)
    actual_mime = mime.from_buffer(file.read(1024))
    file.seek(0)  # Reset cursor after reading

    return actual_mime == 'application/pdf'

# PDF merge page
@app.route('/pdf_merge')
@login_required
def pdf_merge():
    uploaded = session.get('uploaded_pdfs', [])
    merged = session.get('merged_pdf_url', None)
    return render_template(
        'merge_pdf.html',
        files=uploaded,
        pdf_url=merged
    )

# upload_pdf
@app.route('/upload_pdf',  methods=['GET', 'POST'])
@login_required
def upload_pdf():
    # Check if files were submitted
    if 'pdf' not in request.files:
        flash('No files selected', 'danger')
        return redirect(url_for('pdf_merge'))
    
    files = request.files.getlist('pdf')
    
    # Validate at least one file selected
    if not files or all(file.filename == '' for file in files):
        flash('Please select at least one PDF file', 'danger')
        return redirect(url_for('pdf_merge'))

    saved_paths = []
    display_names = []
    timestamp = int(datetime.now().timestamp())
    upload_folder = app.config['PDF_UPLOAD_FOLDER']

    # Create upload directory if not exists
    os.makedirs(upload_folder, exist_ok=True)

    for file in files:
        if file.filename == '':
            continue    

        if not allowed_file(file, file.filename, 'pdf'):
            flash('Invalid file type. Only PDFs allowed', 'danger')
            # Clean up any saved files
            for p in saved_paths:
                if os.path.exists(p):
                    os.remove(p)
            return redirect(url_for('pdf_merge'))   
    

        # Secure filename handling
        original_name = secure_filename(file.filename)
        filename = f"pdf_{timestamp}_{original_name}"
        file_path = os.path.join(upload_folder, filename)

        try:
            file.save(file_path)
            saved_paths.append(file_path)
            display_names.append(original_name)  # Show original name to user
        except Exception as e:
            flash(f'Error saving file: {original_name} - {str(e)}', 'danger')
            # Clean up any saved files
            for p in saved_paths:
                if os.path.exists(p):
                    os.remove(p)
            return redirect(url_for('pdf_merge'))

    # Update session data
    session['uploaded_pdfs'] = display_names
    session['uploaded_pdf_paths'] = saved_paths
    
    # Log the action
    log_action(current_user.id, 'UPLOAD_PDF', f'Uploaded {len(display_names)} PDFs')
    
    flash(f'{len(display_names)} PDF(s) uploaded successfully 🎉', 'success')
    return redirect(url_for('pdf_merge'))

def is_safe_path(base_path, target_path):

    base = os.path.abspath(base_path)
    target = os.path.abspath(target_path)
    return os.path.commonpath([base]) == os.path.commonpath([base, target])

# Helper functions
def is_valid_pdf(file_path):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
            return header == b'%PDF'
    except Exception:
        return False
    

# Process PDFs 
@app.route('/process_pdf', methods=['GET', 'POST']) 
@login_required
def process_pdf():  
    if 'uploaded_pdf_paths' not in session:
        flash('No PDF upload session found', 'danger')
        return redirect(url_for('pdf_merge'))

    upload_folder = app.config['PDF_UPLOAD_FOLDER']
    safe_paths = []
    
    for p in session.get('uploaded_pdf_paths', []):
        if is_safe_path(upload_folder, p) and os.path.exists(p):  
            safe_paths.append(p)

    if not safe_paths:
        flash('No valid PDFs to merge', 'danger')
        return redirect(url_for('pdf_merge'))

    merge_folder = app.config['PDF_MERGE_FOLDER']
    os.makedirs(merge_folder, exist_ok=True)

    output_name = f"merged_{uuid.uuid4().hex}.pdf"
    output_path = os.path.join(merge_folder, output_name)

    try:
        merger = PdfMerger()
        
        for pdf in safe_paths:
            if not is_valid_pdf(pdf):
                filename = os.path.basename(pdf)
                flash(f'Invalid PDF file: {filename}', 'danger')
                raise InvalidPDFError(f"Invalid PDF file: {filename}")
                
            merger.append(pdf)
        
        merger.write(output_path)
        merger.close()
        
    except (PdfReadError, InvalidPDFError) as e:
        app.logger.error(f"PDF merge error: {str(e)}")
        return redirect(url_for('pdf_merge'))
    except Exception as e:
        app.logger.error(f"PDF merge failed: {str(e)}")
        flash('An error occurred during PDF merge', 'danger')
        return redirect(url_for('pdf_merge'))
    
    cleanup_errors = []
    for p in safe_paths:
        try:
            if is_safe_path(upload_folder, p) and os.path.exists(p):  
                os.remove(p)
        except Exception as e:
            cleanup_errors.append(str(e))
            app.logger.error(f"Failed to delete {p}: {str(e)}")

    session.pop('uploaded_pdf_paths', None)
    session.pop('uploaded_pdfs', None)
    session['merged_pdf_url'] = output_name 
    

    record_operation(
    user_id=current_user.id,
    action='MERGE_PDF',
    description=f'Merged {len(safe_paths)} PDF(s) into {output_name}'
    )

    
    if cleanup_errors:
        app.logger.warning(f"Cleanup errors: {', '.join(cleanup_errors)}")
        flash('Some temporary files could not be cleaned up', 'warning')

    flash('PDFs merged successfully! 🎉 The download button is now available', 'success')
    return redirect(url_for('pdf_merge'))   


# download_pdf
@app.route('/download_pdf')
@login_required
def download_pdf(): 

    filename = session.get('merged_pdf_url')
    if not filename: 
        flash('No file to download', 'danger') 
        return redirect(url_for('pdf_merge')) 

    merge_folder = app.config['PDF_MERGE_FOLDER']
    file_path = os.path.join(merge_folder, filename)

    if not os.path.exists(file_path): 
        session.pop('merged_pdf_url', None) 
        flash('The file has expired or was not found', 'danger') 
        return redirect(url_for('pdf_merge')) 

    try:
        if not is_safe_path(merge_folder, file_path):
            flash('Security violation detected', 'danger')
            app.logger.warning(f"Unsafe download attempt: {file_path}")
            return redirect(url_for('pdf_merge'))
        
        response = send_file(file_path, as_attachment=True, download_name='merged_document.pdf')
        
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            app.logger.error(f"Failed to delete merged file: {str(e)}")
        
        session.pop('merged_pdf_url', None)
        
        return response
    except Exception as e:
        app.logger.error(f"Download failed: {str(e)}")
        flash('File download failed', 'danger')
        return redirect(url_for('pdf_merge'))
    

def record_operation(user_id, action, description=None):
    try:
        with sqlite3.connect('database/operation.db') as conn:
            cursor = conn.cursor()

            timestamp = datetime.now(pytz.timezone('Africa/Cairo')).strftime('%Y-%m-%d %H:%M:%S')

            cursor.execute('''
                INSERT INTO logs (user_id, action, description, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (user_id, action, description, timestamp))

            conn.commit()
    except Exception as e:
        print(f"Error logging operation: {e}")
        

# cleanup_files - Uncommented and fixed for proper operation
def cleanup_files():
    folders = [
        app.config['UPLOAD_FOLDER'],
        app.config['PDF_UPLOAD_FOLDER'],
        app.config['PDF_MERGE_FOLDER']
    ]
    
    for folder in folders:
        if not os.path.exists(folder):
            continue
            
        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)
            if os.path.isfile(file_path):
                created_time = datetime.fromtimestamp(os.path.getctime(file_path))
                if (datetime.now() - created_time) > timedelta(hours=24):  # Increased to 24 hours
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        print(f"Error deleting {filename}: {str(e)}")


# Setup scheduler for file cleanup
scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_files, 'interval', hours=1)  # Run cleanup every hour
scheduler.start()

# Register a function to shut down the scheduler when the application exits
import atexit
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    # Ensure upload folders exist
    os.makedirs(app.config['PDF_UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['PDF_MERGE_FOLDER'], exist_ok=True)
    app.run(debug=True)  