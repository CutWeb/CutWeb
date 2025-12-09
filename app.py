from flask import Flask, render_template, session, redirect, url_for, request, flash
from functools import wraps
import json
import os
import secrets
import smtplib
import random
import shutil
from email.mime.text import MIMEText
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle
from datetime import datetime
import pyotp
import qrcode
from io import BytesIO
import base64
from flask_socketio import SocketIO, emit
import requests
from flask_recaptcha import ReCaptcha
from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.recaptcha import RecaptchaField

app = Flask(__name__)
app.config['SECRET_KEY'] = 'irgendwas-sehr-geheimes'
app.config['RECAPTCHA_PUBLIC_KEY'] = 'DEIN_PUBLIC_KEY'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LcUbSYsAAAAAEIMGw_QNH9qZ6F07fsjJst6I6gz'

users_file = "users.json"
reset_tokens = {}  # Temporäre Speicherung von Passwort-Reset-Tokens
two_factor_codes = {}  # Temporäre Speicherung der 2FA-Codes
notifications = []  # Temporäre Speicherung von Benachrichtigungen
security_reports = []

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

load_dotenv()

SMTP_SERVER = os.getenv("smp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))  # Standardwert 587 für TLS
EMAIL_ADDRESS = os.getenv("cutweb0@gmail.com")
EMAIL_PASSWORD = os.getenv("hflk szeq voyc mzjq")

AUDIT_LOG_FILE = 'audit_logs.json'

# Temporäre Speicherung von fehlgeschlagenen Login-Versuchen
login_attempts = {}

# reCAPTCHA Konfiguration
app.config['RECAPTCHA_SITE_KEY'] = os.getenv('6LcUbSYsAAAAAJfnrIyZO6qOQZ1GoyQV7YcSpsHt')
app.config['RECAPTCHA_SECRET_KEY'] = os.getenv('6LcUbSYsAAAAAEIMGw_QNH9qZ6F07fsjJst6I6gz')

recaptcha = ReCaptcha(app)

# Load users from JSON
def load_users():
    try:
        with open(users_file, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open(users_file, 'w') as file:
        json.dump(users, file, indent=4)

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    users = load_users()  # Lade alle Benutzer aus der Datei
    user = users.get(session['username'])  # Hole den aktuellen Benutzer
    
    return render_template('index.html', user=user, users=users)  # Übergib `users` an das Template

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not recaptcha.verify():
            flash("reCAPTCHA-Überprüfung fehlgeschlagen. Bitte versuche es erneut.", "error")
            return redirect(url_for('login'))

        username = request.form['username']
        password = request.form['password']
        if username in login_attempts and login_attempts[username] >= 5:
            flash("Zu viele fehlgeschlagene Versuche. Bitte warte 5 Minuten.", "error")
            return redirect(url_for('login'))

        users = load_users()
        if username in users and users[username]['password'] == password:
            session['username'] = username
            session['2fa_authenticated'] = False

            # 2FA-Code generieren und senden
            code = str(random.randint(100000, 999999))
            two_factor_codes[username] = code
            send_email(users[username]['email'], "Dein 2FA-Code", f"Dein Code lautet: {code}")
            flash("Ein 2FA-Code wurde an deine E-Mail gesendet.", "success")
            return redirect(url_for('two_factor_auth'))
        login_attempts[username] = login_attempts.get(username, 0) + 1
        flash("Benutzername oder Passwort ist falsch", "error")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        users = load_users()
        for username, user in users.items():
            if user['email'] == email:
                # Generiere einen Reset-Token
                token = secrets.token_urlsafe(16)
                reset_tokens[token] = username

                # Passwort-Reset-Link erstellen
                reset_link = f"http://localhost:5001/reset_password/{token}"

                # E-Mail senden
                subject = "Passwort zurücksetzen"
                body = f"Klicke auf den folgenden Link, um dein Passwort zurückzusetzen: {reset_link}"
                send_email(email, subject, body)

                flash(f"Ein Link zum Zurücksetzen des Passworts wurde an {email} gesendet.", "success")
                return redirect(url_for('login'))
        flash("E-Mail-Adresse nicht gefunden", "error")
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    username = reset_tokens.get(token)
    if not username:
        flash("Ungültiger oder abgelaufener Token", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        users = load_users()
        users[username]['password'] = new_password
        save_users(users)
        reset_tokens.pop(token)  # Token entfernen
        flash("Dein Passwort wurde erfolgreich geändert", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/2fa', methods=['GET', 'POST'])
def two_factor_auth():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form['code']
        if session['username'] in two_factor_codes and two_factor_codes[session['username']] == code:
            del two_factor_codes[session['username']]  # Code löschen
            session['2fa_authenticated'] = True
            return redirect(url_for('index'))
        flash("Ungültiger Code", "error")

    return render_template('2fa.html')

@app.route('/2fa/setup', methods=['GET'])
def setup_2fa():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Generiere einen geheimen Schlüssel für den Benutzer
    secret = pyotp.random_base32()
    session['2fa_secret'] = secret

    # Erstelle einen OTP-URI für Google Authenticator
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=session['username'], issuer_name="CutWeb"
    )

    # Generiere einen QR-Code
    qr = qrcode.make(otp_uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template('2fa_setup.html', qr_code=qr_code_base64)

@app.route('/2fa/verify', methods=['POST'])
def verify_2fa():
    if 'username' not in session:
        return redirect(url_for('login'))

    code = request.form['code']
    secret = session.get('2fa_secret')
    totp = pyotp.TOTP(secret)

    if totp.verify(code):
        session['2fa_authenticated'] = True
        flash("2FA erfolgreich eingerichtet!", "success")
        return redirect(url_for('index'))
    else:
        flash("Ungültiger Code", "error")
        return redirect(url_for('setup_2fa'))

def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            users = load_users()
            user = users.get(session['username'])
            if user and user.get('role') == role:
                return func(*args, **kwargs)
            return "Zugriff verweigert", 403
        return wrapper
    return decorator

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = load_users()
    total_users = len(users)
    activities = load_activities()
    return render_template('dashboard.html', total_users=total_users, activities=activities)

# Admin: Benutzerverwaltung
@app.route('/admin/users')
@role_required('admin')
def manage_users():
    users = load_users()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/edit/<username>', methods=['GET', 'POST'])
@role_required('admin')
def edit_user(username):
    users = load_users()
    user = users.get(username)
    if not user:
        flash('Benutzer nicht gefunden', 'error')
        return redirect(url_for('manage_users'))
    if request.method == 'POST':
        user['email'] = request.form['email']
        user['role'] = request.form['role']
        save_users(users)
        log_audit('Benutzer bearbeitet', session['username'], f'Benutzer: {username}')
        flash('Benutzer erfolgreich bearbeitet', 'success')
        return redirect(url_for('manage_users'))
    return render_template('admin_edit_user.html', user=user, username=username)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@role_required('admin')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        users = load_users()
        if username in users:
            flash('Benutzername existiert bereits', 'error')
        else:
            users[username] = {'email': email, 'password': password, 'role': role}
            save_users(users)
            log_audit('Benutzer erstellt', session['username'], f'Benutzer: {username}')
            flash('Benutzer erfolgreich hinzugefügt', 'success')
            return redirect(url_for('manage_users'))
    return render_template('admin_add_user.html')

@app.route('/admin/users/delete/<username>', methods=['POST'])
@role_required('admin')
def delete_user(username):
    users = load_users()
    if username in users:
        del users[username]
        save_users(users)
        log_audit('Benutzer gelöscht', session['username'], f'Benutzer: {username}')
        flash('Benutzer erfolgreich gelöscht', 'success')
    else:
        flash('Benutzer nicht gefunden', 'error')
    return redirect(url_for('manage_users'))

# Admin: Systemstatistiken
@app.route('/admin/stats')
@role_required('admin')
def system_stats():
    stats = {
        "total_users": len(load_users()),
        "uploaded_files": len(load_files()),
        "activities": len(load_activities())
    }
    return render_template('admin_stats.html', stats=stats)

# Admin: Aktivitäten
@app.route('/admin/activity')
@role_required('admin')
def activity_log():
    activities = load_activities()
    return render_template('admin_activity.html', activities=activities)

# Admin: Sicherheitsberichte
@app.route('/admin/security')
@role_required('admin')
def security_reports():
    reports = load_activities()
    return render_template('admin_security.html', reports=reports)

# Admin: Dateien
@app.route('/admin/files')
@role_required('admin')
def manage_files():
    files = load_files()
    return render_template('admin_files.html', files=files)

# Admin: Rollenverwaltung
@app.route('/admin/roles')
@role_required('admin')
def manage_roles():
    roles = ["admin", "moderator", "user"]
    return render_template('admin_roles.html', roles=roles)

@app.route('/admin/notifications', methods=['GET', 'POST'])
@role_required('admin')
def send_notifications():
    if request.method == 'POST':
        message = request.form['message']
        flash(f'Benachrichtigung gesendet: {message}', 'success')
    return render_template('admin_notifications.html')

@app.route('/admin/backup', methods=['GET'])
@role_required('admin')
def backup():
    import shutil
    from datetime import datetime
    backup_folder = 'backups'
    if not os.path.exists(backup_folder):
        os.makedirs(backup_folder)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = os.path.join(backup_folder, f'backup_{timestamp}.json')
    shutil.copy(users_file, backup_file)
    flash(f'Backup erfolgreich erstellt: {backup_file}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/audit')
@role_required('admin')
def audit_logs():
    logs = load_audit_logs()
    return render_template('admin_audit.html', logs=logs)

@app.route('/admin/api_keys', methods=['GET', 'POST'])
@role_required('admin')
def manage_api_keys():
    if request.method == 'POST':
        create_api_key(request.form['name'])
        flash('API-Schlüssel erstellt!', 'success')
    api_keys = get_api_keys()
    return render_template('admin_api_keys.html', api_keys=api_keys)

def send_email(to_email, subject, body):
    try:
        # E-Mail-Nachricht erstellen
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                <h2 style="color: #333;">{subject}</h2>
                <p>{body}</p>
                <hr>
                <p style="font-size: 0.9em; color: #555;">Mit freundlichen Grüßen,<br><strong>CutWeb</strong></p>
            </div>
        </body>
        </html>
        """
        msg = MIMEText(html_body, "html")
        msg["Subject"] = subject
        msg["From"] = f"CutWeb <{EMAIL_ADDRESS}>"
        msg["To"] = to_email

        # Verbindung zum SMTP-Server herstellen
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # TLS aktivieren
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)  # Login
            server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())  # E-Mail senden
        print(f"E-Mail erfolgreich an {to_email} gesendet.")
    except Exception as e:
        print(f"Fehler beim Senden der E-Mail: {e}")

def load_files():
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        return os.listdir(app.config['UPLOAD_FOLDER'])
    return []

def load_activities():
    users = load_users()
    all_activities = []
    for username, user in users.items():
        user_activities = user.get('activities', [])
        all_activities.extend(user_activities)
    return all_activities

def create_backup():
    import shutil
    from datetime import datetime
    backup_folder = 'backups'
    if not os.path.exists(backup_folder):
        os.makedirs(backup_folder)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = os.path.join(backup_folder, f'backup_{timestamp}.json')
    shutil.copy(users_file, backup_file)

def load_audit_logs():
    return []

def create_api_key(name):
    pass

def get_api_keys():
    return []

def log_activity(username, action):
    users = load_users()
    user = users.get(username)
    if user:
        activities = user.setdefault('activities', [])
        activities.append(action)
        save_users(users)

@app.route('/activity')
def activity():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = load_users()
    user = users.get(session['username'])
    return render_template('activity.html', activities=user.get('activities', []))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        users = load_users()
        if username in users:
            flash("Benutzername existiert bereits", "error")
        else:
            users[username] = {"email": email, "password": password, "is_admin": False}
            save_users(users)
            flash("Registrierung erfolgreich", "success")
            return redirect(url_for('login'))
    return render_template('register.html')

# Funktion zur Überprüfung der Dateiendung
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Keine Datei ausgewählt', 'error')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('Keine Datei ausgewählt', 'error')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('Datei erfolgreich hochgeladen', 'success')
            return redirect(url_for('upload_file'))

    return render_template('upload.html')

def add_notification(username, message):
    notifications.append({'username': username, 'message': message})

@app.route('/notifications')
def show_notifications():
    if 'username' not in session:
        return redirect(url_for('login'))

    user_notifications = [n for n in notifications if n['username'] == session['username']]
    return render_template('notifications.html', notifications=user_notifications)

import json

def load_translation(lang):
    filename = f"translations/translation{lang}.json"
    filepath = os.path.join(os.getcwd(), filename)  # Absoluten Pfad erstellen
    with open(filepath, "r") as file:
        return json.load(file)

@app.route('/set_language/<lang>')
def set_language(lang):
    session['language'] = lang
    return redirect(url_for('index'))

@app.context_processor
def inject_translations():
    lang = session.get('language', 'en')
    translations = load_translation(lang)
    return {'t': translations}

@app.context_processor
def inject_load_users():
    return dict(load_users=load_users)

@app.route('/admin')
@role_required('admin')  # Nur Admins dürfen diese Seite aufrufen
def admin_dashboard():
    backup_folder = 'backups'
    if not os.path.exists(backup_folder):
        os.makedirs(backup_folder)  # Ordner erstellen, falls er nicht existiert
    backup_files = os.listdir(backup_folder)  # Liste der Dateien im Backup-Ordner
    return render_template('admin_dashboard.html', backup_files=backup_files)

# Google Drive API Setup
SCOPES = ['https://www.googleapis.com/auth/drive.file']

def authenticate_google_drive():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    return build('drive', 'v3', credentials=creds)

@app.route('/upload_to_drive/<filename>')
@role_required('admin')
def upload_to_drive(filename):
    try:
        drive_service = authenticate_google_drive()
        file_metadata = {'name': filename}
        media = MediaFileUpload(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        file = drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        flash(f'Datei erfolgreich zu Google Drive hochgeladen! Datei-ID: {file.get("id")}', 'success')
    except Exception as e:
        flash(f'Fehler beim Hochladen zu Google Drive: {e}', 'error')
    return redirect(url_for('manage_files'))

@app.route('/admin/restore', methods=['POST'])
@role_required('admin')
def restore_backup():
    backup_file = request.form['backup_file']
    backup_folder = 'backups'
    backup_path = os.path.join(backup_folder, backup_file)
    if os.path.exists(backup_path):
        shutil.copy(backup_path, users_file)
        flash(f'Backup erfolgreich wiederhergestellt: {backup_file}', 'success')
    else:
        flash('Backup-Datei nicht gefunden', 'error')
    return redirect(url_for('admin_dashboard'))

def log_audit(action, username, details=None):
    log_entry = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "action": action,
        "username": username,
        "details": details
    }
    logs = []
    if os.path.exists(AUDIT_LOG_FILE):
        try:
            with open(AUDIT_LOG_FILE, 'r') as f:
                logs = json.load(f)
        except json.JSONDecodeError:
            logs = []  # Wenn die Datei ungültig ist, starte mit einem leeren Array
    else:
        with open(AUDIT_LOG_FILE, 'w') as f:
            json.dump([], f)  # Erstelle die Datei, falls sie nicht existiert
    logs.append(log_entry)
    with open(AUDIT_LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

socketio = SocketIO(app)

@app.route('/send_notification', methods=['POST'])
def send_notification():
    if 'username' not in session:
        return redirect(url_for('login'))

    message = request.form['message']
    username = session['username']
    notification = {'username': username, 'message': message}
    notifications.append(notification)

    # Sende die Benachrichtigung in Echtzeit
    socketio.emit('new_notification', notification, broadcast=True)

    flash("Benachrichtigung gesendet!", "success")
    return redirect(url_for('show_notifications'))

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5002, host='0.0.0.0')
