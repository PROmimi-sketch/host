from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename

import os
import csv
import random
import sqlite3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from tpex import train_llm_with_templates, generate_templates,modify_email_links
import requests
from flask import send_from_directory
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
DEFAULT_ADMIN_USERNAME = 'admin'
DEFAULT_ADMIN_PASSWORD = '123'
DEFAULT_ADMIN_PASSWORD_HASH = generate_password_hash(DEFAULT_ADMIN_PASSWORD)

DEFAULT_USER_USERNAME = 'default_user'
DEFAULT_USER_PASSWORD = 'user123'
DEFAULT_USER_PASSWORD_HASH = generate_password_hash(DEFAULT_USER_PASSWORD)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(80), nullable=False)
    campaign_date = db.Column(db.Date, nullable=False)
    filename = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_run = db.Column(db.Boolean, default=False)  # ✅ Ensure this line exists

import sys
sys.stdout.reconfigure(encoding='utf-8')  # Ensures UTF-8 encoding

print("⚠️ 'campaign' table does not exist. Skipping migration.")




with app.app_context():
    db.create_all()
    import sqlite3

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Check if the 'campaign' table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='campaign';")
    table_exists = cursor.fetchone()

    if table_exists:
        # Check if 'is_run' column exists
        cursor.execute("PRAGMA table_info(campaign);")
        columns = [col[1] for col in cursor.fetchall()]

        if 'is_run' not in columns:
            try:
                # Rename the old table
                cursor.execute("ALTER TABLE campaign RENAME TO campaign_old;")

                # Recreate the campaign table with 'is_run' column
                cursor.execute("""
                    CREATE TABLE campaign (
                        id INTEGER PRIMARY KEY,
                        company_name TEXT NOT NULL,
                        campaign_date DATE NOT NULL,
                        filename TEXT NOT NULL,
                        category TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        is_run BOOLEAN DEFAULT 0
                    );
                """)

                # Copy data from the old table
                cursor.execute("""
                    INSERT INTO campaign (id, company_name, campaign_date, filename, category, created_at)
                    SELECT id, company_name, campaign_date, filename, category, created_at
                    FROM campaign_old;
                """)

                # Drop the old table
                cursor.execute("DROP TABLE campaign_old;")

                conn.commit()
                print("✅ Migration completed. 'is_run' column added successfully.")
            except Exception as e:
                print(f"⚠️ Error adding 'is_run' column: {e}")
        else:
            print("✅ 'is_run' column already exists.")
    else:
        print("⚠️ 'campaign' table does not exist. Skipping migration.")

    conn.close()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')
@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        company_name = request.form.get('company_name')
        password = request.form.get('password')
        user = User.query.filter_by(company_name=company_name).first()
        if user and check_password_hash(user.password, password):
            session['user'] = company_name
            flash(f"Welcome, {company_name}!", "success")
            return redirect(url_for('user_dashboard'))
        else:
            flash("Error: Invalid credentials.", "danger")
            return redirect(url_for('user_login'))
    return render_template('user_login.html')


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()

        if admin and check_password_hash(admin.password, password):
            session['admin'] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for('admin_dashboard'))
        elif username == DEFAULT_ADMIN_USERNAME and password == DEFAULT_ADMIN_PASSWORD:
            session['admin'] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Error: Invalid admin credentials.", "danger")
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        company_name = request.form.get('company_name')
        password = request.form.get('password')

        if not User.query.filter_by(company_name=company_name).first():
            hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
            new_user = User(company_name=company_name, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for('user_login'))
        else:
            flash("Error: Company name already exists.", "danger")
            return redirect(url_for('signup'))

    return render_template('signup.html')
@app.route('/user_dashboard')
def user_dashboard():
    if 'user' not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('user_login'))

    user = session['user']

    # ✅ Fetch only campaigns that have been run (is_run=True)
    campaigns = Campaign.query.filter_by(company_name=user, is_run=True).all()

    # ✅ If at least one campaign is completed, show the "View Report" button
    report_available = len(campaigns) > 0

    return render_template('user_dashboard.html', user=user, report_available=report_available, campaigns=campaigns)

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin' not in session:
        flash("Please log in as an admin first.", "danger")
        return redirect(url_for('admin_login'))

    # Handle admin actions (add/remove admins)
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            username = request.form.get('username')
            password = request.form.get('password')

            if Admin.query.filter_by(username=username).first():
                flash("Admin username already exists.", "danger")
            else:
                hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
                new_admin = Admin(username=username, password=hashed_password)
                db.session.add(new_admin)
                db.session.commit()
                flash("Admin added successfully.", "success")

        elif action == 'remove':
            admin_id = request.form.get('admin_id')
            admin = Admin.query.get(admin_id)

            if admin:
                db.session.delete(admin)
                db.session.commit()
                flash("Admin removed successfully.", "success")

        return redirect(url_for('admin_dashboard'))

    admins = Admin.query.all()
    return render_template('admin_dashboard.html', admins=admins, current_admin=session.get('admin'))


@app.route('/register-campaign', methods=['GET', 'POST'])
def register_campaign():
    if 'user' not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('user_login'))  # ✅ Redirect to login if session is missing

    if request.method == 'POST':
        company_name = session.get('user')  
        campaign_date = request.form.get('date')
        category = request.form.get('category')
        uploaded_file = request.files.get('csvFile')

        if not campaign_date or not uploaded_file or not category:
            flash("All fields are required.", "danger")
            return redirect(url_for('register_campaign'))

        filename = secure_filename(uploaded_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(file_path)

        new_campaign = Campaign(
            company_name=company_name,
            campaign_date=datetime.strptime(campaign_date, '%Y-%m-%d').date(),
            filename=filename,
            category=category
        )

        try:
            db.session.add(new_campaign)
            db.session.commit()
            flash("Campaign registered successfully!", "success")
        except Exception as e:
            db.session.rollback()  # ✅ Prevent partial changes
            flash(f"Error registering campaign: {e}", "danger")

        return redirect(url_for('user_dashboard'))

    return render_template('register_campaign.html')


@app.route('/view-campaigns', methods=['GET'])
def view_campaigns():
    if 'admin' not in session:
        flash("Please log in as an admin first.", "danger")
        return redirect(url_for('admin_login'))

    # Fetch all campaigns sorted by date
    campaigns = Campaign.query.order_by(Campaign.campaign_date.asc()).all()

    return render_template('view_campaigns.html', campaigns=campaigns)



from concurrent.futures import ThreadPoolExecutor, as_completed


            
           
@app.route('/run_campaign/<int:campaign_id>', methods=['POST'])
def run_campaign(campaign_id):
    print(f"🚀 Run Campaign Triggered for ID: {campaign_id}")

    campaign = db.session.get(Campaign, campaign_id)

    if not campaign:
        print("❌ Campaign not found.")
        flash("Campaign not found.", "danger")
        return redirect(url_for('view_campaigns'))

    if campaign.is_run:
        print("⚠️ This campaign has already been run.")
        flash("This campaign has already been run.", "warning")
        return redirect(url_for('view_campaigns'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], campaign.filename)
    if not os.path.exists(file_path):
        print("❌ CSV file not found.")
        flash("CSV file not found.", "danger")
        return redirect(url_for('view_campaigns'))

    print(f"📂 Reading email addresses from: {file_path}")

    email_addresses = []
    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row:
                    email = row[0].strip()
                    if email and email not in email_addresses:
                        email_addresses.append(email)
    except Exception as e:
        print(f"❌ Error reading CSV file: {e}")
        flash("Error reading CSV file.", "danger")
        return redirect(url_for('view_campaigns'))

    print(f"✅ Found {len(email_addresses)} email addresses.")

    if not email_addresses:
        print("⚠️ No valid email addresses found in CSV.")
        flash("No valid email addresses found in CSV.", "warning")
        return redirect(url_for('view_campaigns'))

    print(f"🚀 Generating email templates for category: {campaign.category}")
    try:
        emails = generate_templates(
            train_llm_with_templates('full_email_templates.csv')[0],
            train_llm_with_templates('full_email_templates.csv')[1],
            campaign.category,
            email_addresses
        )
        if not emails:
            print("❌ No email templates found for the selected category.")
            flash("No email templates found for the selected category.", "danger")
            return redirect(url_for('view_campaigns'))
    except Exception as e:
        print(f"❌ Error generating emails: {e}")
        flash(f"Error generating emails: {e}", "danger")
        return redirect(url_for('view_campaigns'))

    successful_emails = 0
    failed_emails = 0

    def send_email_wrapper(email):
        """Function to send emails ensuring correct mapping of userID."""
        nonlocal successful_emails, failed_emails

        if email not in emails or not emails[email]:
            print(f"❌ No valid templates found for {email}. Skipping...")
            return

        subject, body = emails[email][0]
        print(f"📤 Sending email to {email} with subject: {subject}")

        try:
            send_email(email, subject, body)
            print(f"✅ Successfully sent email to {email}")
            successful_emails += 1
        except Exception as e:
            print(f"❌ Failed to send email to {email}: {e}")
            failed_emails += 1

    # ✅ Use ThreadPoolExecutor to run emails concurrently
    max_workers = min(5, len(email_addresses))  
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(send_email_wrapper, email): email for email in email_addresses}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"❌ Error sending email: {e}")

    # ✅ Mark the campaign as "run"
    campaign.is_run = True
    db.session.commit()

    print(f"✅ Campaign run successfully. Sent to {successful_emails} emails.")
    if failed_emails > 0:
        print(f"⚠️ Failed to send to {failed_emails} emails.")

    return redirect(url_for('view_campaigns'))



    
def send_email(to_email, subject, body):
    try:
        EMAIL = 'ramlakman98@gmail.com'
        PASSWORD = 'gzdv ston ffoj btae'  # ✅ Make sure this is correct
        SMTP_SERVER = "smtp.gmail.com"
        SMTP_PORT = 587

        print(f"🔌 Connecting to SMTP server: {SMTP_SERVER}:{SMTP_PORT}")

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        print(f"🔑 Attempting to log in with email: {EMAIL}")
        server.login(EMAIL, PASSWORD)

        print(f"📤 Sending email to: {to_email}")
        msg = MIMEMultipart()
        msg['From'] = EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        
        server.sendmail(EMAIL, to_email, msg.as_string())
        server.quit()

        print(f"✅ Email successfully sent to {to_email}")
    except smtplib.SMTPAuthenticationError as auth_err:
        print(f"❌ SMTP Authentication Error: {auth_err}")
    except smtplib.SMTPConnectError as conn_err:
        print(f"❌ SMTP Connection Error: {conn_err}")
    except smtplib.SMTPRecipientsRefused as rec_err:
        print(f"❌ SMTP Recipient Refused: {rec_err}")
    except Exception as e:
        print(f"❌ General Error: {e}")

# ✅ Loggly API Configuration
LOGGLY_API_URL = "https://nithin3131.loggly.com/apiv2/events/iterate?q=*&from=-48H&until=now&size=100"

LOGGLY_API_TOKEN = '1bddcb24-d715-4091-844c-a50008c1cb14'             # Replace with your Loggly API Token
@app.route('/view-report', methods=['GET'])
def view_report():
    if 'user' not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('user_login'))

    company_name = session.get('user')
    campaigns = Campaign.query.filter_by(company_name=company_name, is_run=True).all()

    if not campaigns:
        flash("No completed campaigns found.", "warning")
        return redirect(url_for('user_dashboard'))

    # ✅ Process each completed campaign
    for campaign in campaigns:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], campaign.filename)
        if not os.path.exists(file_path):
            continue  # Skip if CSV file is missing

        # ✅ Read email addresses from the uploaded CSV file
        email_addresses = []
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row:
                    email_addresses.append(row[0].strip())

        user_ids = [email.split('@')[0] for email in email_addresses]

        # ✅ Define report filename
        report_filename = f"{company_name}_{campaign.id}_report.xlsx"
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)

        # ✅ Fetch Loggly logs and update the report every time
        fetch_loggly_data(user_ids, report_path)

    flash("✅ Report updated with the latest logs!", "success")
    return redirect(url_for('user_dashboard'))


import requests
import pandas as pd
import os

def fetch_loggly_data(user_ids, report_path):
    """Fetch logs from Loggly & update the Excel report with the latest timestamps & IPs."""
    headers = {"Authorization": f"Bearer {LOGGLY_API_TOKEN}"}

    try:
        response = requests.get(LOGGLY_API_URL, headers=headers)
        response.raise_for_status()
        data = response.json()
        logs = data.get('events', [])

        latest_clicks = {}  # Store only the latest click per user

        for log in logs:
            event_data = log.get('event', {}).get('json', {})  # ✅ Avoid KeyErrors
            user_id = event_data.get('userID', '')
            timestamp = event_data.get('timestamp', '')
            ip = event_data.get('ip', '')

            if user_id and timestamp:
                if user_id not in latest_clicks or timestamp > latest_clicks[user_id]['timestamp']:
                    latest_clicks[user_id] = {"timestamp": timestamp, "ip": ip}

        # ✅ Ensure report file exists before modifying it
        if os.path.exists(report_path):
            df = pd.read_excel(report_path)
        else:
            df = pd.DataFrame(columns=["Email ID", "Clicked", "Timestamp", "IP Address"])

        # ✅ Ensure all expected email IDs are in the report
        existing_emails = set(df["Email ID"].tolist()) if "Email ID" in df.columns else set()

        for user_id in user_ids:
            email = f"{user_id}@example.com"  # Adjust domain logic as needed

            if email not in existing_emails:
                df = pd.concat([df, pd.DataFrame([{"Email ID": email, "Clicked": 0, "Timestamp": "", "IP Address": ""}])], ignore_index=True)

            # ✅ Update click data if available
            if user_id in latest_clicks:
                df.loc[df["Email ID"] == email, "Clicked"] = 1  # Mark as clicked
                df.loc[df["Email ID"] == email, "Timestamp"] = latest_clicks[user_id]["timestamp"]
                df.loc[df["Email ID"] == email, "IP Address"] = latest_clicks[user_id]["ip"]

        # ✅ Save updated report
        df.to_excel(report_path, index=False)
        print("✅ Report updated with latest Loggly data.")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching logs from Loggly: {e}")








@app.route('/get-latest-report')
def get_latest_report():
    """Returns the latest completed campaigns as JSON for frontend auto-refresh."""
    if 'user' not in session:
        return {"error": "User not logged in"}, 401

    company_name = session['user']
    campaigns = Campaign.query.filter_by(company_name=company_name, is_run=True).all()

    report_data = []
    for campaign in campaigns:
        report_data.append({"Campaign ID": campaign.id})

    return report_data, 200  # ✅ Send data in JSON format



@app.route('/admin-view-report/<company_name>/<int:campaign_id>')
def admin_view_report(company_name, campaign_id):
    """Admin triggers report generation and downloads the report."""
    report_filename = f"{company_name}_{campaign_id}_report.xlsx"
    report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)

    # ✅ If the report doesn't exist, generate it using `view_report`
    if not os.path.exists(report_path):
        flash("Generating report, please wait...", "info")
        view_report()  # Calls the existing view_report function to generate the report

    # ✅ Check again after generating
    if not os.path.exists(report_path):
        flash("Report generation failed. Please try again.", "danger")
        return redirect(url_for('view_campaigns'))

    return send_from_directory(app.config['UPLOAD_FOLDER'], report_filename, as_attachment=True)


@app.route('/download-csv/<filename>')
def download_csv(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(file_path):
        flash("CSV file not found.", "danger")
        return redirect(url_for('view_campaigns'))

    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/download-report/<company_name>/<int:campaign_id>')
def download_report(company_name, campaign_id):
    if 'user' not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('user_login'))

    if session['user'] != company_name:
        flash("Unauthorized access to report!", "danger")
        return redirect(url_for('user_dashboard'))

    report_filename = f"{company_name}_{campaign_id}_report.xlsx"
    report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)

    # ✅ Debugging Log
    print(f"📁 Checking for report file: {report_path}")

    # ✅ Check if file exists before downloading
    if not os.path.exists(report_path):
        print(f"❌ Report file not found: {report_filename}")
        flash("Report file not found. Please try again later.", "danger")
        return redirect(url_for('user_dashboard'))

    print(f"✅ Report file found! Sending to user: {report_filename}")
    return send_from_directory(app.config['UPLOAD_FOLDER'], report_filename, as_attachment=True)

        
        
        
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('admin', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
