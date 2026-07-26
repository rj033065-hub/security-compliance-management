from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# ─────────────────────────────────────────────
# Department
# ─────────────────────────────────────────────
class Department(db.Model):
    __tablename__ = 'departments'
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(100), nullable=False, unique=True)
    code          = db.Column(db.String(20),  nullable=False, unique=True)
    description   = db.Column(db.Text,        nullable=True)
    manager_name  = db.Column(db.String(100), nullable=True)
    created_at    = db.Column(db.DateTime,    default=datetime.utcnow)

    users = db.relationship('User', backref='department', lazy=True)

# ─────────────────────────────────────────────
# User  (core auth model)
# ─────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id                  = db.Column(db.Integer, primary_key=True)
    full_name           = db.Column(db.String(100), nullable=False)
    username            = db.Column(db.String(80),  nullable=False, unique=True)
    email               = db.Column(db.String(120), nullable=False, unique=True, index=True)
    password_hash       = db.Column(db.String(256), nullable=False)
    role                = db.Column(db.String(30),  nullable=False, default='Employee')
    # role values: 'Super Admin', 'Admin', 'Auditor', 'Employee'
    department_id       = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=True)
    phone               = db.Column(db.String(30),  nullable=True)
    profile_image       = db.Column(db.String(255), default='default_avatar.png')
    job_title           = db.Column(db.String(100), nullable=True)
    status              = db.Column(db.String(20),  default='Active')  # Active / Inactive
    must_change_password= db.Column(db.Boolean,     default=False)
    last_login          = db.Column(db.DateTime,    nullable=True)
    created_at          = db.Column(db.DateTime,    default=datetime.utcnow)
    updated_at          = db.Column(db.DateTime,    default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    tasks_assigned  = db.relationship('Task', foreign_keys='Task.assigned_to_id', backref='assignee',   lazy=True)
    tasks_created   = db.relationship('Task', foreign_keys='Task.assigned_by_id', backref='creator',    lazy=True)
    evidence_up     = db.relationship('Evidence', foreign_keys='Evidence.employee_id',  backref='uploader',  lazy=True)
    evidence_rev    = db.relationship('Evidence', foreign_keys='Evidence.reviewer_id',  backref='reviewer',  lazy=True)
    audits_as       = db.relationship('Audit',   foreign_keys='Audit.auditor_id',       backref='auditor',   lazy=True)
    notifications   = db.relationship('Notification', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_super_admin(self):
        return self.role == 'Super Admin'

    @property
    def is_admin(self):
        return self.role in ['Super Admin', 'Admin']

    @property
    def is_auditor(self):
        return self.role in ['Super Admin', 'Admin', 'Auditor']

# ─────────────────────────────────────────────
# Compliance Framework
# ─────────────────────────────────────────────
class Framework(db.Model):
    __tablename__ = 'frameworks'
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False, unique=True)
    code        = db.Column(db.String(30),  nullable=False, unique=True)
    version     = db.Column(db.String(20),  nullable=False, default='1.0')
    description = db.Column(db.Text,        nullable=True)
    category    = db.Column(db.String(50),  nullable=True)
    status      = db.Column(db.String(20),  default='Enabled')
    created_at  = db.Column(db.DateTime,    default=datetime.utcnow)

    policies = db.relationship('Policy',  backref='framework', lazy=True, cascade='all, delete-orphan')
    controls = db.relationship('Control', backref='framework', lazy=True, cascade='all, delete-orphan')
    audits   = db.relationship('Audit',   backref='framework', lazy=True)

# ─────────────────────────────────────────────
# Security Policy
# ─────────────────────────────────────────────
class Policy(db.Model):
    __tablename__ = 'policies'
    id            = db.Column(db.Integer, primary_key=True)
    title         = db.Column(db.String(200), nullable=False)
    policy_code   = db.Column(db.String(50),  nullable=False, unique=True)
    framework_id  = db.Column(db.Integer, db.ForeignKey('frameworks.id'), nullable=False)
    category      = db.Column(db.String(100), nullable=True)
    description   = db.Column(db.Text,        nullable=True)
    version       = db.Column(db.String(20),  default='1.0')
    status        = db.Column(db.String(20),  default='Active')  # Draft / Active / Archived
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at    = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    creator = db.relationship('User', foreign_keys=[created_by_id])

# ─────────────────────────────────────────────
# Security Control
# ─────────────────────────────────────────────
class Control(db.Model):
    __tablename__ = 'controls'
    id           = db.Column(db.Integer, primary_key=True)
    framework_id = db.Column(db.Integer, db.ForeignKey('frameworks.id'), nullable=False)
    control_code = db.Column(db.String(50),  nullable=False)
    name         = db.Column(db.String(200), nullable=False)
    category     = db.Column(db.String(100), nullable=True)
    description  = db.Column(db.Text,        nullable=True)
    risk_level   = db.Column(db.String(20),  default='Medium')   # Low / Medium / High / Critical
    status       = db.Column(db.String(30),  default='Not Implemented')

    tasks = db.relationship('Task',           backref='control', lazy=True)
    risks = db.relationship('RiskAssessment', backref='control', lazy=True)

# ─────────────────────────────────────────────
# Compliance Task
# ─────────────────────────────────────────────
class Task(db.Model):
    __tablename__ = 'tasks'
    id              = db.Column(db.Integer, primary_key=True)
    title           = db.Column(db.String(200), nullable=False)
    description     = db.Column(db.Text,        nullable=True)
    control_id      = db.Column(db.Integer, db.ForeignKey('controls.id'), nullable=True)
    assigned_to_id  = db.Column(db.Integer, db.ForeignKey('users.id'),    nullable=False)
    assigned_by_id  = db.Column(db.Integer, db.ForeignKey('users.id'),    nullable=False)
    priority        = db.Column(db.String(20),  default='Medium')  # Low / Medium / High / Critical
    due_date        = db.Column(db.Date,        nullable=False)
    status          = db.Column(db.String(30),  default='Pending')
    completed_at    = db.Column(db.DateTime,    nullable=True)
    created_at      = db.Column(db.DateTime,    default=datetime.utcnow)

    evidences = db.relationship('Evidence', backref='task', lazy=True, cascade='all, delete-orphan')

# ─────────────────────────────────────────────
# Evidence
# ─────────────────────────────────────────────
class Evidence(db.Model):
    __tablename__ = 'evidences'
    id               = db.Column(db.Integer, primary_key=True)
    task_id          = db.Column(db.Integer, db.ForeignKey('tasks.id'),    nullable=False)
    employee_id      = db.Column(db.Integer, db.ForeignKey('users.id'),    nullable=False)
    file_path        = db.Column(db.String(255), nullable=False)
    file_name        = db.Column(db.String(255), nullable=False)
    file_type        = db.Column(db.String(50),  nullable=True)
    file_size        = db.Column(db.Integer,     nullable=True)
    review_status    = db.Column(db.String(30),  default='Pending')  # Pending / Approved / Rejected
    reviewer_comments= db.Column(db.Text,        nullable=True)
    reviewer_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    uploaded_at      = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at      = db.Column(db.DateTime, nullable=True)

# ─────────────────────────────────────────────
# Audit Engagement
# ─────────────────────────────────────────────
class Audit(db.Model):
    __tablename__ = 'audits'
    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(200), nullable=False)
    audit_code      = db.Column(db.String(50),  nullable=False, unique=True)
    framework_id    = db.Column(db.Integer, db.ForeignKey('frameworks.id'), nullable=False)
    auditor_id      = db.Column(db.Integer, db.ForeignKey('users.id'),      nullable=False)
    start_date      = db.Column(db.Date,        nullable=False)
    end_date        = db.Column(db.Date,        nullable=False)
    scope           = db.Column(db.Text,        nullable=True)
    status          = db.Column(db.String(30),  default='Scheduled')
    findings        = db.Column(db.Text,        nullable=True)
    recommendations = db.Column(db.Text,        nullable=True)
    final_status    = db.Column(db.String(30),  default='Pending')
    created_at      = db.Column(db.DateTime,    default=datetime.utcnow)

# ─────────────────────────────────────────────
# Risk Assessment
# ─────────────────────────────────────────────
class RiskAssessment(db.Model):
    __tablename__ = 'risk_assessments'
    id              = db.Column(db.Integer, primary_key=True)
    title           = db.Column(db.String(200), nullable=False)
    control_id      = db.Column(db.Integer, db.ForeignKey('controls.id'), nullable=True)
    asset_scope     = db.Column(db.String(200), nullable=True)
    likelihood      = db.Column(db.Integer, default=3)   # 1–5
    impact          = db.Column(db.Integer, default=3)   # 1–5
    risk_score      = db.Column(db.Integer, default=9)   # likelihood × impact
    risk_level      = db.Column(db.String(20), default='Medium')
    mitigations     = db.Column(db.Text,       nullable=True)
    assessed_by_id  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    assessor = db.relationship('User', foreign_keys=[assessed_by_id])

# ─────────────────────────────────────────────
# Notification
# ─────────────────────────────────────────────
class Notification(db.Model):
    __tablename__ = 'notifications'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title      = db.Column(db.String(150), nullable=False)
    message    = db.Column(db.Text,        nullable=False)
    type       = db.Column(db.String(20),  default='info')  # info / success / warning / danger
    is_read    = db.Column(db.Boolean,     default=False)
    link       = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime,   default=datetime.utcnow)

# ─────────────────────────────────────────────
# Activity / Audit Log
# ─────────────────────────────────────────────
class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    user_name  = db.Column(db.String(100), nullable=False)
    user_role  = db.Column(db.String(50),  nullable=True)
    action     = db.Column(db.String(100), nullable=False)
    details    = db.Column(db.Text,        nullable=True)
    ip_address = db.Column(db.String(45),  nullable=True)
    created_at = db.Column(db.DateTime,   default=datetime.utcnow)
