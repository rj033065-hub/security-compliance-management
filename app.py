"""
app.py – Security Compliance Management System
Multi-Tenant Flask application with database-backed RBAC authentication and Company isolation.
"""
import os
import random
from datetime import datetime, date
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, flash, jsonify, send_file, abort)
from flask_login import (LoginManager, login_user, logout_user,
                          login_required, current_user)
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from config import Config
from models import (db, Company, User, Department, Framework, Policy, Control,
                    Task, Evidence, Audit, RiskAssessment, Notification, ActivityLog)
from services.ai_service import AIConsultant
from services.report_service import ReportGenerator
from services.log_service import log_activity
from services.timezone_service import get_ist_now, to_ist, format_ist

# ─────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view      = 'login'
login_manager.login_message   = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ─────────────────────────────────────────────
# Helper: Seed Default Company Data
# ─────────────────────────────────────────────
def seed_company_defaults(company):
    """Seed standard departments, frameworks, and controls for a newly created company."""
    depts = [
        Department(company_id=company.id, name="Cybersecurity & Governance", code="SEC-01", manager_name="Security Lead", description="Oversees security, policies, audits, and risk."),
        Department(company_id=company.id, name="IT Infrastructure & Systems", code="IT-01",  manager_name="IT Admin", description="Manages servers, cloud, networks, and endpoints."),
        Department(company_id=company.id, name="Software Engineering",          code="DEV-01", manager_name="Lead Engineer", description="Application development and Secure SDLC."),
        Department(company_id=company.id, name="Human Resources",               code="HR-01",  manager_name="HR Lead", description="Employee onboarding, training, and compliance."),
        Department(company_id=company.id, name="Finance & Operations",          code="OPS-01", manager_name="Ops Manager", description="Financial operations and regulatory reporting."),
    ]
    db.session.add_all(depts)
    db.session.flush()

    fw_iso   = Framework(company_id=company.id, name="ISO/IEC 27001:2022",       code="ISO-27001",   version="2022", category="International Standard", status="Enabled",
                         description="International standard for ISMS, defining security controls across Annex A domains.")
    fw_nist  = Framework(company_id=company.id, name="NIST Cybersecurity Framework", code="NIST-CSF-2.0", version="2.0", category="Government Standard",   status="Enabled",
                         description="Framework for managing cybersecurity risk (Govern, Identify, Protect, Detect, Respond, Recover).")
    fw_pci   = Framework(company_id=company.id, name="PCI DSS v4.0",               code="PCI-DSS-4.0", version="4.0", category="Financial Security",      status="Enabled",
                         description="Payment Card Industry Data Security Standard for protecting cardholder data.")
    fw_hipaa = Framework(company_id=company.id, name="HIPAA Security Rule",         code="HIPAA-SEC",   version="2023", category="Healthcare Security",     status="Enabled",
                         description="Safeguards for electronic Protected Health Information (ePHI).")
    db.session.add_all([fw_iso, fw_nist, fw_pci, fw_hipaa])
    db.session.flush()

    c1 = Control(company_id=company.id, framework_id=fw_iso.id,  control_code="A.5.15",    name="Access Control & Password Policy",      category="Identity & Access",    risk_level="High",     status="Implemented",    description="Strong passwords and automatic session timeout.")
    c2 = Control(company_id=company.id, framework_id=fw_iso.id,  control_code="A.8.5",     name="Multi-Factor Authentication (MFA)",     category="Identity & Access",    risk_level="Critical",  status="Implemented",    description="MFA for all cloud services, VPNs, admin portals.")
    c3 = Control(company_id=company.id, framework_id=fw_iso.id,  control_code="A.8.7",     name="Antivirus & EDR Endpoint Protection",   category="Endpoint Protection",  risk_level="High",     status="Implemented",    description="Next-Gen EDR with automated virus definition updates.")
    c4 = Control(company_id=company.id, framework_id=fw_iso.id,  control_code="A.8.20",    name="Firewall & Network Security Config",    category="Network Security",     risk_level="High",     status="Implemented",    description="Restrictive firewall rules and IDS/IPS systems.")
    c5 = Control(company_id=company.id, framework_id=fw_iso.id,  control_code="A.8.24",    name="Full Disk Encryption (BitLocker)",      category="Data Protection",      risk_level="Critical",  status="Implemented",    description="AES-256 encryption on all laptops and mobile devices.")
    c6 = Control(company_id=company.id, framework_id=fw_nist.id, control_code="PR.IP-01",  name="OS & Vulnerability Patching",          category="System Maintenance",   risk_level="High",     status="Partial",        description="Apply critical patches within 14 days of publication.")
    c7 = Control(company_id=company.id, framework_id=fw_nist.id, control_code="PR.IP-04",  name="Automated Backup & Disaster Recovery",  category="Resilience",           risk_level="High",     status="Implemented",    description="Encrypted daily off-site backups; quarterly recovery tests.")
    c8 = Control(company_id=company.id, framework_id=fw_hipaa.id,control_code="§ 164.308", name="Security Awareness & Phishing Training",category="Personnel",            risk_level="Medium",    status="Partial",        description="Mandatory quarterly cybersecurity awareness training.")
    db.session.add_all([c1,c2,c3,c4,c5,c6,c7,c8])
    db.session.flush()
    return depts, [fw_iso, fw_nist, fw_pci, fw_hipaa], [c1,c2,c3,c4,c5,c6,c7,c8]


# ─────────────────────────────────────────────
# User loader
# ─────────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ─────────────────────────────────────────────
# RBAC decorator
# ─────────────────────────────────────────────
def role_required(*allowed_roles):
    """Restrict view to users whose role is in allowed_roles."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role not in allowed_roles:
                flash('Access Denied: You are not authorised to view this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─────────────────────────────────────────────
# Context processor – available in all templates
# ─────────────────────────────────────────────
@app.context_processor
def inject_globals():
    unread = 0
    company = None
    if current_user.is_authenticated:
        unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        company = current_user.company
    return dict(unread_notifications_count=unread, current_company=company)


@app.template_filter('format_datetime')
def format_datetime_filter(value, fmt="%d %b %Y, %I:%M:%S %p", default="N/A"):
    if not value:
        return default
    return format_ist(value, fmt=fmt, default=default)


@app.template_filter('to_ist')
def to_ist_filter(value):
    return to_ist(value)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def compliance_score():
    if not current_user.is_authenticated or not current_user.company_id:
        return 100
    cid = current_user.company_id
    total = Control.query.filter_by(company_id=cid).count()
    if not total:
        return 100
    impl    = Control.query.filter_by(company_id=cid, status='Implemented').count()
    partial = Control.query.filter_by(company_id=cid, status='Partial').count()
    return int(((impl + partial * 0.5) / total) * 100)


def _normalize_text(value):
    return (value or '').strip()


def validate_password(password):
    if len(password) < 8:
        return False, 'Password must be at least 8 characters.'
    if not any(ch.isupper() for ch in password) or not any(ch.isdigit() for ch in password):
        return False, 'Password must include at least one uppercase letter and one number.'
    return True, ''


def create_notification(user_id, title, message, link=None, notification_type='info'):
    u = User.query.get(user_id)
    cid = u.company_id if u else (current_user.company_id if current_user.is_authenticated else None)
    notification = Notification(
        company_id=cid,
        user_id=user_id,
        title=title,
        message=message,
        type=notification_type,
        link=link,
    )
    db.session.add(notification)
    return notification


def _dashboard_stats():
    if not current_user.is_authenticated or not current_user.company_id:
        return {}
    cid = current_user.company_id

    risk_summary = {
        'critical': RiskAssessment.query.filter_by(company_id=cid, risk_level='Critical').count(),
        'high': RiskAssessment.query.filter_by(company_id=cid, risk_level='High').count(),
        'medium': RiskAssessment.query.filter_by(company_id=cid, risk_level='Medium').count(),
        'low': RiskAssessment.query.filter_by(company_id=cid, risk_level='Low').count(),
    }
    my_tasks = Task.query.filter_by(company_id=cid, assigned_to_id=current_user.id).count()
    my_evidence = Evidence.query.filter_by(company_id=cid, employee_id=current_user.id).count()

    return {
        'total_employees':   User.query.filter_by(company_id=cid).count(),
        'total_users':       User.query.filter_by(company_id=cid).count(),
        'total_departments': Department.query.filter_by(company_id=cid).count(),
        'total_policies':    Policy.query.filter_by(company_id=cid, status='Active').count(),
        'total_frameworks':  Framework.query.filter_by(company_id=cid, status='Enabled').count(),
        'compliance_score':  compliance_score(),
        'pending_tasks':     Task.query.filter_by(company_id=cid).filter(Task.status.in_(['Pending', 'In Progress', 'Overdue', 'Under Review'])).count(),
        'completed_tasks':   Task.query.filter_by(company_id=cid, status='Completed').count(),
        'overdue_tasks':     Task.query.filter_by(company_id=cid).filter(Task.status != 'Completed', Task.due_date < date.today()).count(),
        'high_risks':        RiskAssessment.query.filter_by(company_id=cid).filter(RiskAssessment.risk_level.in_(['High', 'Critical'])).count(),
        'active_audits':     Audit.query.filter_by(company_id=cid).filter(Audit.status.in_(['Scheduled', 'In Progress'])).count(),
        'total_audits':      Audit.query.filter_by(company_id=cid).count(),
        'pending_reviews':   Evidence.query.filter_by(company_id=cid, review_status='Pending').count(),
        'my_tasks':          my_tasks,
        'my_evidence':        my_evidence,
        'risk_summary':      risk_summary,
        'recent_activities': ActivityLog.query.filter_by(company_id=cid).order_by(ActivityLog.created_at.desc()).limit(6).all(),
    }


def _ensure_default_superadmin():
    """Create a default company and Super Admin if none exists yet."""
    company = Company.query.first()
    if not company:
        company = Company(name="Acme Cybersecurity Corp", code="ACME", contact_email=app.config['DEFAULT_SUPERADMIN_EMAIL'], status="Active")
        db.session.add(company)
        db.session.flush()
        seed_company_defaults(company)

    if User.query.filter_by(role='Super Admin').first():
        return

    dept = Department.query.filter_by(company_id=company.id).first()
    sa = User(
        company_id            = company.id,
        full_name             = app.config['DEFAULT_SUPERADMIN_NAME'],
        username              = 'superadmin',
        email                 = app.config['DEFAULT_SUPERADMIN_EMAIL'],
        role                  = 'Super Admin',
        department_id         = dept.id if dept else None,
        job_title             = 'Chief Information Security Officer',
        status                = 'Active',
        must_change_password  = True,
    )
    sa.set_password(app.config['DEFAULT_SUPERADMIN_PASSWORD'])
    db.session.add(sa)
    db.session.commit()
    log_activity('System Init', f'Default Super Admin created: {sa.email}')


# ─────────────────────────────────────────────
# =============================================
#  AUTHENTICATION & COMPANY REGISTRATION ROUTES
# =============================================
# ─────────────────────────────────────────────

@app.before_request
def enforce_access_controls():
    public_endpoints = {'landing', 'login', 'register', 'register_company', 'forgot_password', 'reset_password_token', 'login_google', 'static'}
    if request.endpoint in public_endpoints:
        return None
    if current_user.is_authenticated and current_user.status != 'Active':
        logout_user()
        flash('Your account is currently inactive. Please contact an administrator.', 'warning')
        return redirect(url_for('landing'))
    return None


@app.route('/')
def landing():
    return render_template('landing.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        login_input = _normalize_text(request.form.get('username', '')).lower()
        password    = request.form.get('password', '')
        remember    = bool(request.form.get('remember'))

        if not login_input or not password:
            flash('Please enter both your username/email and password.', 'warning')
            return redirect(url_for('login'))

        user = User.query.filter(
            (User.email == login_input) | (User.username == login_input)
        ).first()

        if not user or not user.check_password(password):
            log_activity('Failed Login', f'Input: {login_input}')
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

        if user.status != 'Active':
            flash('This account is currently inactive. Please contact an administrator.', 'warning')
            return redirect(url_for('login'))

        login_user(user, remember=remember)
        user.last_login = get_ist_now()
        db.session.commit()
        log_activity('Login', f'{user.email} authenticated as {user.role}')

        if user.must_change_password:
            flash('Security requirement: please set a new password before continuing.', 'warning')
            return redirect(url_for('force_change_password'))

        flash(f'Welcome back, {user.full_name}!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('auth/login.html')


@app.route('/register-company', methods=['GET', 'POST'])
def register_company():
    """Register a brand new company and auto-create its Super Admin user."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        company_name  = _normalize_text(request.form.get('company_name', ''))
        company_code  = _normalize_text(request.form.get('company_code', '')).upper()
        contact_email = _normalize_text(request.form.get('contact_email', '')).lower()
        full_name     = _normalize_text(request.form.get('full_name', ''))
        username      = _normalize_text(request.form.get('username', '')).lower()
        email         = _normalize_text(request.form.get('email', '')).lower()
        password      = request.form.get('password', '')

        if not company_name or not full_name or not username or not email or not password:
            flash('Please complete all required fields.', 'danger')
            return redirect(url_for('register_company'))

        valid, msg = validate_password(password)
        if not valid:
            flash(msg, 'danger')
            return redirect(url_for('register_company'))

        if Company.query.filter_by(name=company_name).first():
            flash('A company with that name is already registered.', 'danger')
            return redirect(url_for('register_company'))

        if User.query.filter_by(username=username).first():
            flash('Username is already taken.', 'danger')
            return redirect(url_for('register_company'))

        if User.query.filter_by(email=email).first():
            flash('Email address is already registered.', 'danger')
            return redirect(url_for('register_company'))

        code = company_code or company_name.replace(' ', '').upper()[:8]
        company = Company(name=company_name, code=code, contact_email=contact_email or email, status='Active')
        db.session.add(company)
        db.session.flush()

        depts, _, _ = seed_company_defaults(company)
        sec_dept = depts[0] if depts else None

        superadmin = User(
            company_id=company.id,
            full_name=full_name,
            username=username,
            email=email,
            role='Super Admin',
            department_id=sec_dept.id if sec_dept else None,
            job_title='Super Admin & Executive Officer',
            status='Active',
            must_change_password=False
        )
        superadmin.set_password(password)
        db.session.add(superadmin)
        db.session.commit()

        log_activity('Company Registered', f'Company {company_name} registered with SuperAdmin {email}')
        flash(f'Company "{company_name}" registered successfully! Super Admin account created. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register_company.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Employee self-registration under an existing company."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    companies = Company.query.filter_by(status='Active').all()

    if request.method == 'POST':
        company_id= request.form.get('company_id')
        full_name = _normalize_text(request.form.get('full_name', ''))
        username  = _normalize_text(request.form.get('username', '')).lower()
        email     = _normalize_text(request.form.get('email', '')).lower()
        password  = request.form.get('password', '')
        dept_id   = request.form.get('department_id')

        if not company_id or not full_name or not username or not email:
            flash('Please complete all required fields.', 'danger')
            return redirect(url_for('register'))
        valid, msg = validate_password(password)
        if not valid:
            flash(msg, 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        u = User(company_id=int(company_id), full_name=full_name, username=username, email=email,
                 role='Employee', department_id=dept_id or None, status='Active')
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        log_activity('Registration', f'New employee registered: {email}')
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html', companies=companies)


@app.route('/api/company/<int:cid>/departments')
def api_company_departments(cid):
    """API endpoint to load departments dynamically for a selected company."""
    depts = Department.query.filter_by(company_id=cid).all()
    return jsonify([{'id': d.id, 'name': d.name, 'code': d.code} for d in depts])


@app.route('/force-change-password', methods=['GET', 'POST'])
@login_required
def force_change_password():
    if not current_user.must_change_password:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        pw  = request.form.get('new_password', '')
        cpw = request.form.get('confirm_password', '')

        valid, msg = validate_password(pw)
        if not valid:
            flash(msg, 'danger')
            return redirect(url_for('force_change_password'))
        if pw != cpw:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('force_change_password'))

        current_user.set_password(pw)
        current_user.must_change_password = False
        db.session.commit()
        log_activity('Password Changed', 'Mandatory initial password change completed')
        flash('Password updated – welcome to your dashboard!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('auth/force_change_password.html')


@app.route('/login/google', methods=['GET', 'POST'])
def login_google():
    """Simulated Google SSO – accepts any employee email."""
    google_email = (request.form.get('google_email') or
                    request.args.get('google_email') or
                    'employee@compliance.com').strip().lower()

    user = User.query.filter_by(email=google_email).first()
    if not user:
        company = Company.query.first()
        uname = google_email.split('@')[0]
        if User.query.filter_by(username=uname).first():
            uname = f"{uname}_{random.randint(100, 999)}"
        dept = Department.query.filter_by(company_id=company.id).first() if company else None
        user = User(
            company_id    = company.id if company else None,
            full_name     = uname.replace('.', ' ').title(),
            username      = uname,
            email         = google_email,
            role          = 'Employee',
            department_id = dept.id if dept else None,
            job_title     = 'Google SSO Employee',
            status        = 'Active',
        )
        user.set_password(os.urandom(24).hex())
        db.session.add(user)
        db.session.commit()

    if user.status != 'Active':
        flash('Invalid email or password.', 'danger')
        return redirect(url_for('login'))

    login_user(user, remember=True)
    user.last_login = get_ist_now()
    db.session.commit()
    log_activity('Google SSO Login', f'{google_email}')
    flash(f'Signed in with Google as {user.full_name}!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user  = User.query.filter_by(email=email).first()
        if user:
            token     = serializer.dumps(email, salt='pwd-reset')
            reset_url = url_for('reset_password_token', token=token, _external=True)
            log_activity('Password Reset Requested', f'Token for {email}')
            flash(f'Reset link (dev mode): {reset_url}', 'info')
        else:
            flash('If that email exists a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('auth/forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = serializer.loads(token, salt='pwd-reset', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        pw  = request.form.get('password', '')
        cpw = request.form.get('confirm_password', '')
        if len(pw) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return redirect(request.url)
        if pw != cpw:
            flash('Passwords do not match.', 'danger')
            return redirect(request.url)
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(pw)
            db.session.commit()
            log_activity('Password Reset', f'Reset for {email}')
            flash('Password reset successfully! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('auth/reset_password.html', token=token)


@app.route('/logout')
@login_required
def logout():
    log_activity('Logout', f'{current_user.email} logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))


# ─────────────────────────────────────────────
# =============================================
#  DASHBOARDS  (role-specific)
# =============================================
# ─────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.must_change_password:
        return redirect(url_for('force_change_password'))

    cid = current_user.company_id
    stats  = _dashboard_stats()
    logs   = ActivityLog.query.filter_by(company_id=cid).order_by(ActivityLog.created_at.desc()).limit(6).all()
    notifs = (Notification.query
              .filter_by(company_id=cid, user_id=current_user.id)
              .order_by(Notification.created_at.desc())
              .limit(5).all())

    role = current_user.role
    if role == 'Super Admin':
        return render_template('dashboard/super_admin.html', stats=stats, recent_logs=logs, notifications=notifs)
    elif role == 'Admin':
        return render_template('dashboard/admin.html', stats=stats, recent_logs=logs, notifications=notifs)
    elif role == 'Auditor':
        return render_template('dashboard/auditor.html', stats=stats, recent_logs=logs, notifications=notifs)
    else:
        return render_template('dashboard/employee.html', stats=stats, recent_logs=logs, notifications=notifs)


# ─────────────────────────────────────────────
# =============================================
#  USER MANAGEMENT  (Super Admin + Admin)
# =============================================
# ─────────────────────────────────────────────

USERS_PER_PAGE = 10

@app.route('/users')
@login_required
@role_required('Super Admin', 'Admin', 'Auditor')
def users():
    q           = request.args.get('q', '').strip()
    role_f      = request.args.get('role_filter', '').strip()
    dept_f      = request.args.get('dept_filter', '').strip()
    page        = request.args.get('page', 1, type=int)

    cid   = current_user.company_id
    query = User.query.filter_by(company_id=cid)
    if q:
        query = query.filter(
            (User.full_name.ilike(f'%{q}%')) |
            (User.email.ilike(f'%{q}%')) |
            (User.username.ilike(f'%{q}%'))
        )
    if role_f:
        query = query.filter_by(role=role_f)
    if dept_f and dept_f.isdigit():
        query = query.filter_by(department_id=int(dept_f))

    pagination  = query.order_by(User.created_at.desc()).paginate(page=page, per_page=USERS_PER_PAGE, error_out=False)
    departments = Department.query.filter_by(company_id=cid).all()

    return render_template('users/index.html',
                           users=pagination.items,
                           pagination=pagination,
                           departments=departments,
                           search_q=q, role_filter=role_f, dept_filter=dept_f)


@app.route('/users/create', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def create_user():
    cid       = current_user.company_id
    full_name = _normalize_text(request.form.get('full_name', ''))
    username  = _normalize_text(request.form.get('username', '')).lower()
    email     = _normalize_text(request.form.get('email', '')).lower()
    role      = request.form.get('role', 'Employee')
    dept_id   = request.form.get('department_id')
    phone     = _normalize_text(request.form.get('phone', ''))
    password  = request.form.get('password', '')

    if not full_name or not username or not email or not password:
        flash('Please provide all required account details.', 'danger')
        return redirect(url_for('users'))

    valid, msg = validate_password(password)
    if not valid:
        flash(msg, 'danger')
        return redirect(url_for('users'))

    if current_user.role == 'Admin' and role not in ['Employee', 'Auditor']:
        flash('Admins can only create Employee or Auditor accounts.', 'danger')
        return redirect(url_for('users'))

    if User.query.filter_by(email=email).first():
        flash('An account with that email already exists.', 'danger')
        return redirect(url_for('users'))
    if User.query.filter_by(username=username).first():
        flash('Username is already taken.', 'danger')
        return redirect(url_for('users'))

    u = User(company_id=cid, full_name=full_name, username=username, email=email,
             role=role, department_id=dept_id or None, phone=phone, status='Active')
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    create_notification(u.id, 'Welcome to the system', 'Your account has been created. Please review your profile.', link='/profile', notification_type='info')
    log_activity('User Created', f'{email} ({role})')
    flash(f'Account for {email} ({role}) created successfully.', 'success')
    return redirect(url_for('users'))


@app.route('/users/<int:uid>/edit', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def edit_user(uid):
    cid = current_user.company_id
    u   = User.query.filter_by(id=uid, company_id=cid).first_or_404()

    if current_user.role == 'Admin' and u.role == 'Super Admin':
        flash('Access denied. Admins cannot edit Super Admin accounts.', 'danger')
        return redirect(url_for('users'))

    full_name = _normalize_text(request.form.get('full_name', u.full_name))
    email     = _normalize_text(request.form.get('email', u.email)).lower()
    username  = _normalize_text(request.form.get('username', u.username)).lower()
    phone     = _normalize_text(request.form.get('phone', ''))

    if not full_name:
        flash('Full name cannot be empty.', 'danger')
        return redirect(url_for('users'))

    if email and email != u.email:
        existing = User.query.filter_by(email=email).first()
        if existing and existing.id != u.id:
            flash('An account with that email address already exists.', 'danger')
            return redirect(url_for('users'))
        u.email = email

    if username and username != u.username:
        existing = User.query.filter_by(username=username).first()
        if existing and existing.id != u.id:
            flash('Username is already taken by another account.', 'danger')
            return redirect(url_for('users'))
        u.username = username

    u.full_name     = full_name
    u.phone         = phone
    dept_id         = request.form.get('department_id')
    u.department_id = int(dept_id) if dept_id else None

    if current_user.role == 'Super Admin':
        u.role = request.form.get('role', u.role)

    db.session.commit()
    log_activity('User Edited', f'{u.email}')
    flash(f'User details for {u.email} updated successfully.', 'success')
    return redirect(url_for('users'))


@app.route('/users/<int:uid>/toggle-status', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def toggle_user_status(uid):
    cid = current_user.company_id
    u   = User.query.filter_by(id=uid, company_id=cid).first_or_404()

    if u.role == 'Super Admin' and u.id == current_user.id:
        flash('You cannot deactivate your own Super Admin account.', 'danger')
        return redirect(url_for('users'))

    if current_user.role == 'Admin' and u.role in ['Super Admin', 'Admin']:
        flash('Admins cannot change the status of other Admin or Super Admin accounts.', 'danger')
        return redirect(url_for('users'))

    u.status = 'Inactive' if u.status == 'Active' else 'Active'
    db.session.commit()
    log_activity('User Status Changed', f'{u.email} → {u.status}')
    flash(f'Status for {u.email} changed to {u.status}.', 'success')
    return redirect(url_for('users'))


@app.route('/users/<int:uid>/reset-password', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def admin_reset_password(uid):
    cid = current_user.company_id
    u   = User.query.filter_by(id=uid, company_id=cid).first_or_404()

    if current_user.role == 'Admin' and u.role == 'Super Admin':
        flash('Access denied. Admins cannot reset Super Admin passwords.', 'danger')
        return redirect(url_for('users'))

    pw = request.form.get('new_password', '')
    valid, msg = validate_password(pw)
    if not valid:
        flash(msg, 'danger')
        return redirect(url_for('users'))

    u.set_password(pw)
    u.must_change_password = True
    db.session.commit()
    create_notification(u.id, 'Password reset', 'Your password has been reset by an administrator.', link='/profile', notification_type='warning')
    log_activity('Password Reset (Admin)', f'Reset for {u.email}')
    flash(f'Password for {u.email} reset successfully.', 'success')
    return redirect(url_for('users'))


@app.route('/users/<int:uid>/delete', methods=['POST'])
@login_required
@role_required('Super Admin')
def delete_user(uid):
    if uid == current_user.id:
        flash('You cannot delete your own active account.', 'danger')
        return redirect(url_for('users'))

    cid = current_user.company_id
    u   = User.query.filter_by(id=uid, company_id=cid).first_or_404()
    email = u.email

    reassign_user_id = current_user.id
    Task.query.filter_by(company_id=cid, assigned_to_id=u.id).update({'assigned_to_id': reassign_user_id})
    Task.query.filter_by(company_id=cid, assigned_by_id=u.id).update({'assigned_by_id': reassign_user_id})
    Evidence.query.filter_by(company_id=cid, employee_id=u.id).update({'employee_id': reassign_user_id})
    Evidence.query.filter_by(company_id=cid, reviewer_id=u.id).update({'reviewer_id': None})
    Audit.query.filter_by(company_id=cid, auditor_id=u.id).update({'auditor_id': reassign_user_id})
    Policy.query.filter_by(company_id=cid, created_by_id=u.id).update({'created_by_id': reassign_user_id})
    RiskAssessment.query.filter_by(company_id=cid, assessed_by_id=u.id).update({'assessed_by_id': reassign_user_id})
    Notification.query.filter_by(user_id=u.id).delete()
    ActivityLog.query.filter_by(user_id=u.id).update({'user_id': None})

    db.session.delete(u)
    db.session.commit()
    log_activity('User Deleted', f'{email}')
    flash(f'User account {email} permanently deleted.', 'warning')
    return redirect(url_for('users'))


# ─────────────────────────────────────────────
# =============================================
#  COMPLIANCE GOVERNANCE ROUTES
# =============================================
# ─────────────────────────────────────────────

@app.route('/frameworks')
@login_required
def frameworks():
    cid = current_user.company_id
    return render_template('frameworks/index.html', frameworks=Framework.query.filter_by(company_id=cid).all())


@app.route('/frameworks/add', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def add_framework():
    cid = current_user.company_id
    fw = Framework(
        company_id=cid,
        name=request.form['name'], code=request.form['code'],
        version=request.form.get('version', '1.0'),
        category=request.form.get('category'),
        description=request.form.get('description'),
        status='Enabled'
    )
    db.session.add(fw); db.session.commit()
    log_activity('Framework Added', fw.name)
    flash(f'Framework {fw.name} added.', 'success')
    return redirect(url_for('frameworks'))


@app.route('/frameworks/<int:fw_id>/toggle', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def toggle_framework(fw_id):
    cid = current_user.company_id
    fw = Framework.query.filter_by(id=fw_id, company_id=cid).first_or_404()
    fw.status = 'Disabled' if fw.status == 'Enabled' else 'Enabled'
    db.session.commit()
    flash(f'Framework {fw.name} is now {fw.status}.', 'info')
    return redirect(url_for('frameworks'))


@app.route('/frameworks/<int:fw_id>/delete', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def delete_framework(fw_id):
    cid = current_user.company_id
    fw = Framework.query.filter_by(id=fw_id, company_id=cid).first_or_404()
    db.session.delete(fw); db.session.commit()
    log_activity('Framework Deleted', fw.name)
    flash('Framework deleted.', 'success')
    return redirect(url_for('frameworks'))


@app.route('/policies')
@login_required
def policies():
    cid = current_user.company_id
    return render_template('policies/index.html',
                           policies=Policy.query.filter_by(company_id=cid).all(),
                           frameworks=Framework.query.filter_by(company_id=cid, status='Enabled').all())


@app.route('/policies/create', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def create_policy():
    cid = current_user.company_id
    p = Policy(
        company_id=cid,
        title=request.form['title'], policy_code=request.form['policy_code'],
        framework_id=request.form['framework_id'],
        category=request.form.get('category'),
        description=request.form.get('description'),
        status='Active', created_by_id=current_user.id
    )
    db.session.add(p); db.session.commit()
    log_activity('Policy Created', p.policy_code)
    flash(f'Policy {p.policy_code} created.', 'success')
    return redirect(url_for('policies'))


@app.route('/policies/<int:pid>/archive', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def archive_policy(pid):
    cid = current_user.company_id
    p = Policy.query.filter_by(id=pid, company_id=cid).first_or_404()
    p.status = 'Archived'; db.session.commit()
    flash(f'Policy {p.policy_code} archived.', 'warning')
    return redirect(url_for('policies'))


@app.route('/controls')
@login_required
def controls():
    cid = current_user.company_id
    return render_template('controls/index.html',
                           controls=Control.query.filter_by(company_id=cid).all(),
                           frameworks=Framework.query.filter_by(company_id=cid, status='Enabled').all())


@app.route('/controls/create', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def create_control():
    cid = current_user.company_id
    c = Control(
        company_id=cid,
        framework_id=request.form['framework_id'],
        control_code=request.form['control_code'],
        name=request.form['name'],
        category=request.form.get('category'),
        risk_level=request.form.get('risk_level', 'Medium'),
        description=request.form.get('description'),
        status='Not Implemented'
    )
    db.session.add(c); db.session.commit()
    log_activity('Control Added', c.control_code)
    flash(f'Control {c.control_code} added.', 'success')
    return redirect(url_for('controls'))


@app.route('/controls/<int:cid_val>/status', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin', 'Auditor')
def update_control_status(cid_val):
    cid = current_user.company_id
    c = Control.query.filter_by(id=cid_val, company_id=cid).first_or_404()
    c.status = request.form.get('status', c.status)
    db.session.commit()
    flash(f'Control {c.control_code} → {c.status}.', 'success')
    return redirect(url_for('controls'))


# ─────────────────────────────────────────────
# Tasks
# ─────────────────────────────────────────────

@app.route('/tasks')
@login_required
def tasks():
    cid = current_user.company_id
    if current_user.role in ['Super Admin', 'Admin', 'Auditor']:
        task_list = Task.query.filter_by(company_id=cid).order_by(Task.due_date).all()
    else:
        task_list = (Task.query
                     .filter_by(company_id=cid, assigned_to_id=current_user.id)
                     .order_by(Task.due_date).all())
    return render_template('tasks/index.html',
                           tasks=task_list,
                           users=User.query.filter_by(company_id=cid, status='Active').all(),
                           controls=Control.query.filter_by(company_id=cid).all())


@app.route('/tasks/create', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def create_task():
    cid = current_user.company_id
    title = _normalize_text(request.form.get('title', ''))
    assigned_to_id = request.form.get('assigned_to_id')
    if not title or not assigned_to_id:
        flash('Task title and assignee are required.', 'danger')
        return redirect(url_for('tasks'))
    try:
        due = datetime.strptime(request.form['due_date'], '%Y-%m-%d').date()
    except ValueError:
        flash('Please provide a valid due date.', 'danger')
        return redirect(url_for('tasks'))
    t = Task(
        company_id=cid,
        title=title,
        description=_normalize_text(request.form.get('description')),
        control_id=request.form.get('control_id') or None,
        assigned_to_id=assigned_to_id,
        assigned_by_id=current_user.id,
        priority=request.form.get('priority', 'Medium'),
        due_date=due, status='Pending'
    )
    db.session.add(t)
    create_notification(t.assigned_to_id, 'New Task Assigned', f"Task '{t.title}' assigned. Due: {due}", link='/tasks', notification_type='info')
    db.session.commit()
    log_activity('Task Created', t.title)
    flash('Task assigned.', 'success')
    return redirect(url_for('tasks'))


# ─────────────────────────────────────────────
# Evidence
# ─────────────────────────────────────────────

@app.route('/evidence')
@login_required
def evidence():
    cid = current_user.company_id
    if current_user.role in ['Super Admin', 'Admin', 'Auditor']:
        evs   = Evidence.query.filter_by(company_id=cid).order_by(Evidence.uploaded_at.desc()).all()
        tsks  = Task.query.filter_by(company_id=cid).all()
    else:
        evs   = (Evidence.query
                 .filter_by(company_id=cid, employee_id=current_user.id)
                 .order_by(Evidence.uploaded_at.desc()).all())
        tsks  = Task.query.filter_by(company_id=cid, assigned_to_id=current_user.id).all()
    return render_template('evidence/index.html',
                           evidences=evs, tasks=tsks,
                           selected_task_id=request.args.get('task_id'))


@app.route('/evidence/upload', methods=['POST'])
@login_required
def upload_evidence():
    cid = current_user.company_id
    task_id = request.form.get('task_id')
    f       = request.files.get('evidence_file')
    if not f or not f.filename:
        flash('No file selected.', 'danger')
        return redirect(url_for('evidence'))

    fname = secure_filename(f.filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
    f.save(save_path)

    ev = Evidence(
        company_id=cid,
        task_id=task_id, employee_id=current_user.id,
        file_path=f'uploads/{fname}', file_name=fname,
        file_type=f.content_type,
        file_size=os.path.getsize(save_path),
        review_status='Pending'
    )
    db.session.add(ev)
    task = Task.query.filter_by(id=task_id, company_id=cid).first()
    if task:
        task.status = 'Under Review'
        create_notification(task.assigned_to_id, 'Evidence Submitted', 'A new evidence file has been uploaded for review.', link='/evidence', notification_type='success')
    db.session.commit()
    log_activity('Evidence Uploaded', fname)
    flash('Evidence uploaded – pending review.', 'success')
    return redirect(url_for('evidence'))


@app.route('/evidence/<int:eid>/review', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin', 'Auditor')
def review_evidence(eid):
    cid = current_user.company_id
    ev = Evidence.query.filter_by(id=eid, company_id=cid).first_or_404()
    ev.review_status     = request.form.get('review_status')
    ev.reviewer_comments = request.form.get('reviewer_comments')
    ev.reviewer_id       = current_user.id
    ev.reviewed_at       = get_ist_now()
    if ev.review_status == 'Approved' and ev.task:
        ev.task.status       = 'Completed'
        ev.task.completed_at = get_ist_now()
    db.session.commit()
    log_activity('Evidence Reviewed', f'#{eid} → {ev.review_status}')
    flash(f'Evidence {ev.review_status}.', 'success')
    return redirect(url_for('evidence'))


# ─────────────────────────────────────────────
# Audits
# ─────────────────────────────────────────────

@app.route('/audits')
@login_required
def audits():
    cid = current_user.company_id
    return render_template('audits/index.html',
                           audits=Audit.query.filter_by(company_id=cid).order_by(Audit.start_date.desc()).all(),
                           frameworks=Framework.query.filter_by(company_id=cid, status='Enabled').all(),
                           auditors=User.query.filter_by(company_id=cid).filter(User.role.in_(
                               ['Auditor', 'Admin', 'Super Admin'])).all())


@app.route('/audits/create', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin', 'Auditor')
def create_audit():
    cid = current_user.company_id
    name = _normalize_text(request.form.get('name', ''))
    audit_code = _normalize_text(request.form.get('audit_code', ''))
    if not name or not audit_code:
        flash('Audit name and code are required.', 'danger')
        return redirect(url_for('audits'))
    try:
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
    except ValueError:
        flash('Please provide valid audit dates.', 'danger')
        return redirect(url_for('audits'))
    a = Audit(
        company_id=cid,
        name=name, audit_code=audit_code,
        framework_id=request.form['framework_id'],
        auditor_id=request.form['auditor_id'],
        start_date=start_date,
        end_date=end_date,
        scope=request.form.get('scope'),
        status='Scheduled', final_status='Pending'
    )
    db.session.add(a); db.session.commit()
    create_notification(a.auditor_id, 'Audit Scheduled', f'Audit {a.audit_code} has been scheduled for you.', link='/audits', notification_type='info')
    log_activity('Audit Scheduled', a.audit_code)
    flash(f'Audit {a.audit_code} scheduled.', 'success')
    return redirect(url_for('audits'))


@app.route('/audits/<int:aid>/findings', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin', 'Auditor')
def update_audit_findings(aid):
    cid = current_user.company_id
    a = Audit.query.filter_by(id=aid, company_id=cid).first_or_404()
    a.status          = request.form.get('status', a.status)
    a.final_status    = request.form.get('final_status', a.final_status)
    a.findings        = request.form.get('findings')
    a.recommendations = request.form.get('recommendations')
    db.session.commit()
    flash('Audit findings saved.', 'success')
    return redirect(url_for('audits'))


# ─────────────────────────────────────────────
# Risk Assessment
# ─────────────────────────────────────────────

@app.route('/risk-assessment')
@login_required
def risk_assessment():
    cid = current_user.company_id
    return render_template('risk/index.html',
                           risks=RiskAssessment.query.filter_by(company_id=cid).order_by(
                               RiskAssessment.risk_score.desc()).all(),
                           controls=Control.query.filter_by(company_id=cid).all())


@app.route('/risk-assessment/create', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin', 'Auditor')
def create_risk():
    cid   = current_user.company_id
    lkl   = int(request.form.get('likelihood', 3))
    imp   = int(request.form.get('impact', 3))
    score = lkl * imp
    level = 'Low' if score <= 5 else ('Medium' if score <= 12 else ('High' if score <= 19 else 'Critical'))
    title = _normalize_text(request.form.get('title', ''))
    if not title:
        flash('Risk title is required.', 'danger')
        return redirect(url_for('risk_assessment'))
    r = RiskAssessment(
        company_id=cid,
        title=title,
        asset_scope=request.form.get('asset_scope'),
        likelihood=lkl, impact=imp,
        risk_score=score, risk_level=level,
        mitigations=request.form.get('mitigations'),
        assessed_by_id=current_user.id
    )
    db.session.add(r); db.session.commit()
    log_activity('Risk Assessed', f'{r.title} → {level}')
    flash(f'Risk Score {score} ({level}).', 'success')
    return redirect(url_for('risk_assessment'))


# ─────────────────────────────────────────────
# AI Studio
# ─────────────────────────────────────────────

@app.route('/ai-studio')
@login_required
def ai_studio():
    cid     = current_user.company_id
    ctrls   = Control.query.filter_by(company_id=cid).all()
    missing = AIConsultant.analyze_missing_controls(ctrls)
    highr   = RiskAssessment.query.filter_by(company_id=cid).filter(
        RiskAssessment.risk_level.in_(['High', 'Critical'])).all()
    summary = AIConsultant.generate_executive_risk_summary(
        highr, Audit.query.filter_by(company_id=cid).count(),
        Task.query.filter_by(company_id=cid).filter(Task.status != 'Completed').count())
    return render_template('ai/studio.html', missing_controls=missing, ai_risk_summary=summary)


@app.route('/api/ai/chat', methods=['POST'])
@login_required
def ai_chat_api():
    data = request.get_json(silent=True) or {}
    query = data.get('query', '') if isinstance(data, dict) else ''
    role = getattr(current_user, 'role', 'Admin') if current_user.is_authenticated else 'Admin'
    return jsonify(AIConsultant.answer_query(query, role=role))


# ─────────────────────────────────────────────
# Reports
# ─────────────────────────────────────────────

def _report_stats():
    cid = current_user.company_id
    return {
        'total_employees':  User.query.filter_by(company_id=cid).count(),
        'total_policies':   Policy.query.filter_by(company_id=cid, status='Active').count(),
        'total_frameworks': Framework.query.filter_by(company_id=cid, status='Enabled').count(),
        'compliance_score': compliance_score(),
        'pending_tasks':    Task.query.filter_by(company_id=cid).filter(Task.status.in_(['Pending', 'In Progress', 'Overdue'])).count(),
        'completed_tasks':  Task.query.filter_by(company_id=cid, status='Completed').count(),
        'high_risks':       RiskAssessment.query.filter_by(company_id=cid).filter(RiskAssessment.risk_level.in_(['High', 'Critical'])).count(),
        'total_audits':     Audit.query.filter_by(company_id=cid).count(),
    }


@app.route('/reports')
@login_required
def reports():
    return render_template('reports/index.html')


@app.route('/reports/export/excel')
@login_required
def export_excel_report():
    cid = current_user.company_id
    buf = ReportGenerator.generate_excel_compliance_report(
        _report_stats(), Framework.query.filter_by(company_id=cid).all(),
        Task.query.filter_by(company_id=cid).all(), Audit.query.filter_by(company_id=cid).all(),
        RiskAssessment.query.filter_by(company_id=cid).all())
    log_activity('Report Exported', 'Excel')
    return send_file(buf,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True,
                     download_name=f"Compliance_Report_{get_ist_now().strftime('%Y%m%d_%H%M%S')}.xlsx")


@app.route('/reports/export/pdf')
@login_required
def export_pdf_report():
    cid = current_user.company_id
    buf = ReportGenerator.generate_pdf_report(
        _report_stats(), Framework.query.filter_by(company_id=cid).all(),
        Task.query.filter_by(company_id=cid).all(), Audit.query.filter_by(company_id=cid).all(),
        RiskAssessment.query.filter_by(company_id=cid).all())
    log_activity('Report Exported', 'PDF')
    return send_file(buf, mimetype='application/pdf', as_attachment=True,
                     download_name=f"Compliance_Audit_{get_ist_now().strftime('%Y%m%d_%H%M%S')}.pdf")


# ─────────────────────────────────────────────
# Departments
# ─────────────────────────────────────────────

@app.route('/departments')
@login_required
@role_required('Super Admin', 'Admin')
def departments():
    cid = current_user.company_id
    return render_template('departments/index.html', departments=Department.query.filter_by(company_id=cid).all())


@app.route('/departments/create', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def create_department():
    cid = current_user.company_id
    d = Department(
        company_id=cid,
        name=request.form['name'], code=request.form['code'],
        manager_name=request.form.get('manager_name'),
        description=request.form.get('description'))
    db.session.add(d); db.session.commit()
    log_activity('Department Created', d.name)
    flash(f'Department {d.name} created.', 'success')
    return redirect(url_for('departments'))


# ─────────────────────────────────────────────
# Notifications
# ─────────────────────────────────────────────

@app.route('/notifications')
@login_required
def notifications():
    cid = current_user.company_id
    notifs = (Notification.query
              .filter_by(company_id=cid, user_id=current_user.id)
              .order_by(Notification.created_at.desc()).all())
    for n in notifs:
        n.is_read = True
    db.session.commit()
    return render_template('notifications/index.html', notifications=notifs)


# ─────────────────────────────────────────────
# Activity Logs  (Super Admin + Admin only)
# ─────────────────────────────────────────────

@app.route('/logs')
@login_required
@role_required('Super Admin')
def logs():
    cid    = current_user.company_id
    page   = request.args.get('page', 1, type=int)
    q      = request.args.get('q', '').strip()
    qry    = ActivityLog.query.filter_by(company_id=cid)
    if q:
        qry = qry.filter(
            ActivityLog.user_name.ilike(f'%{q}%') |
            ActivityLog.action.ilike(f'%{q}%'))
    pag = qry.order_by(ActivityLog.created_at.desc()).paginate(page=page, per_page=20)
    return render_template('logs/index.html', logs=pag.items, pagination=pag, search_q=q)


# ─────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────

@app.route('/settings')
@login_required
@role_required('Super Admin', 'Admin')
def settings():
    return render_template('settings/index.html')


@app.route('/settings/save', methods=['POST'])
@login_required
@role_required('Super Admin', 'Admin')
def save_settings():
    log_activity('Settings Saved', 'System preferences updated')
    flash('Settings saved.', 'success')
    return redirect(url_for('settings'))


# ─────────────────────────────────────────────
# User Profile  (any authenticated user)
# ─────────────────────────────────────────────

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        fn  = request.form.get('full_name', '').strip()
        jt  = request.form.get('job_title', '')
        ph  = request.form.get('phone', '')
        pw  = request.form.get('new_password', '')
        cpw = request.form.get('confirm_password', '')

        if fn:
            current_user.full_name = fn
        current_user.job_title = jt
        current_user.phone     = ph

        if pw:
            if len(pw) < 8:
                flash('Password must be at least 8 characters.', 'danger')
                return redirect(url_for('profile'))
            if pw != cpw:
                flash('Passwords do not match.', 'danger')
                return redirect(url_for('profile'))
            current_user.set_password(pw)
            flash('Password updated.', 'success')

        db.session.commit()
        log_activity('Profile Updated', current_user.email)
        flash('Profile saved.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile/index.html')


# ─────────────────────────────────────────────
# APPLICATION STARTUP
# ─────────────────────────────────────────────

with app.app_context():
    db.create_all()
    _ensure_default_superadmin()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
