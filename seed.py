"""
seed.py – Database seeding script
Run once after fresh installation: python seed.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime, timedelta
from app import app
from models import (db, Company, User, Department, Framework, Policy, Control, Task,
                    Evidence, Audit, RiskAssessment, Notification, ActivityLog)


def seed_company_defaults(company):
    """Seed standard departments, frameworks, and controls for a new company."""
    # ── Departments ──
    depts = [
        Department(company_id=company.id, name="Cybersecurity & Governance", code="SEC-01", manager_name="Security Lead", description="Oversees security, policies, audits, and risk."),
        Department(company_id=company.id, name="IT Infrastructure & Systems", code="IT-01",  manager_name="IT Admin", description="Manages servers, cloud, networks, and endpoints."),
        Department(company_id=company.id, name="Software Engineering",          code="DEV-01", manager_name="Lead Engineer", description="Application development and Secure SDLC."),
        Department(company_id=company.id, name="Human Resources",               code="HR-01",  manager_name="HR Lead", description="Employee onboarding, training, and compliance."),
        Department(company_id=company.id, name="Finance & Operations",          code="OPS-01", manager_name="Ops Manager", description="Financial operations and regulatory reporting."),
    ]
    db.session.add_all(depts)
    db.session.flush()

    # ── Frameworks ──
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

    # ── Controls ──
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


def seed():
    with app.app_context():
        db.drop_all()
        db.create_all()
        print("Tables created.")

        # ── Create Company A: Acme Cybersecurity ─────────────────────────────
        c_acme = Company(name="Acme Cybersecurity Corp", code="ACME", contact_email="admin@acme.com", status="Active")
        db.session.add(c_acme)
        db.session.flush()

        depts_a, fws_a, ctrls_a = seed_company_defaults(c_acme)
        sec_dept_a, it_dept_a, dev_dept_a, hr_dept_a = depts_a[0], depts_a[1], depts_a[2], depts_a[3]
        fw_iso_a, fw_nist_a, fw_pci_a, fw_hipaa_a = fws_a[0], fws_a[1], fws_a[2], fws_a[3]

        # Acme Users
        superadmin_a = User(
            company_id=c_acme.id, full_name="Acme SuperAdmin", username="superadmin",
            email="superadmin@compliance.com", role="Super Admin",
            department_id=sec_dept_a.id, job_title="Chief Information Security Officer",
            phone="+1-555-0100", status="Active", must_change_password=True
        )
        superadmin_a.set_password("Admin@123")

        admin_a = User(
            company_id=c_acme.id, full_name="Sarah Jenkins", username="admin",
            email="admin@compliance.com", role="Admin",
            department_id=sec_dept_a.id, job_title="Security Compliance Manager",
            phone="+1-555-0101", status="Active", must_change_password=False
        )
        admin_a.set_password("password123")

        auditor_a = User(
            company_id=c_acme.id, full_name="Michael Vance", username="auditor",
            email="auditor@compliance.com", role="Auditor",
            department_id=sec_dept_a.id, job_title="Lead Security Auditor",
            phone="+1-555-0102", status="Active", must_change_password=False
        )
        auditor_a.set_password("password123")

        emp1_a = User(
            company_id=c_acme.id, full_name="David Miller", username="employee",
            email="employee@compliance.com", role="Employee",
            department_id=it_dept_a.id, job_title="Systems Administrator",
            phone="+1-555-0103", status="Active", must_change_password=False
        )
        emp1_a.set_password("password123")

        db.session.add_all([superadmin_a, admin_a, auditor_a, emp1_a])
        db.session.commit()

        # Policies for Acme
        p1 = Policy(company_id=c_acme.id, title="Global Access Control & Identity Policy", policy_code="POL-AC-01", framework_id=fw_iso_a.id, category="Access Control", status="Active", created_by_id=admin_a.id, description="Mandatory MFA and zero-trust access control.")
        p2 = Policy(company_id=c_acme.id, title="Data Cryptography & Key Management Policy", policy_code="POL-CRYPTO-02", framework_id=fw_iso_a.id, category="Data Security", status="Active", created_by_id=admin_a.id, description="AES-256 encryption at rest, TLS 1.3 in transit.")
        db.session.add_all([p1, p2])
        db.session.commit()

        # Tasks for Acme
        today = datetime.utcnow().date()
        t1 = Task(company_id=c_acme.id, title="Verify MFA Enforcement on All Corporate Portals", control_id=ctrls_a[1].id, assigned_to_id=emp1_a.id, assigned_by_id=admin_a.id, priority="Critical", due_date=today+timedelta(5), status="Completed", completed_at=datetime.utcnow()-timedelta(1), description="Confirm 100% MFA enrollment.")
        t2 = Task(company_id=c_acme.id, title="Deploy Q3 Windows Server Security Patches", control_id=ctrls_a[5].id, assigned_to_id=emp1_a.id, assigned_by_id=admin_a.id, priority="High", due_date=today+timedelta(3), status="Under Review", description="Apply vendor security patches.")
        db.session.add_all([t1, t2])
        db.session.commit()

        # Evidence for Acme
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        e1 = Evidence(company_id=c_acme.id, task_id=t1.id, employee_id=emp1_a.id, file_path="uploads/mfa_report.pdf", file_name="mfa_report.pdf", file_type="application/pdf", file_size=2048500, review_status="Approved", reviewer_id=auditor_a.id, reviewer_comments="MFA report verified.", uploaded_at=datetime.utcnow()-timedelta(1), reviewed_at=datetime.utcnow())
        db.session.add(e1)
        db.session.commit()

        # Audits & Risks for Acme
        a1 = Audit(company_id=c_acme.id, name="Annual ISO 27001 Surveillance Audit Q3", audit_code="AUD-ISO-2026-01", framework_id=fw_iso_a.id, auditor_id=auditor_a.id, start_date=today-timedelta(10), end_date=today+timedelta(5), scope="Corporate infrastructure.", status="In Progress", findings="Patch management needs improvement.", recommendations="Automate OS patching.", final_status="Partially Compliant")
        r1 = RiskAssessment(company_id=c_acme.id, title="Unpatched Endpoint OS Vulnerabilities", control_id=ctrls_a[5].id, asset_scope="Corporate Workstations", likelihood=4, impact=4, risk_score=16, risk_level="High", assessed_by_id=admin_a.id, mitigations="Deploy automated WSUS.")
        db.session.add_all([a1, r1])
        db.session.commit()

        # Activity log & Notification for Acme
        db.session.add(Notification(company_id=c_acme.id, user_id=emp1_a.id, title="Overdue Task", message="'Submit Security Certificates' is overdue.", type="danger", link="/tasks"))
        db.session.add(ActivityLog(company_id=c_acme.id, user_id=admin_a.id, user_name=admin_a.email, user_role="Admin", action="Policy Created", details="POL-AC-01 created.", ip_address="127.0.0.1"))
        db.session.commit()

        # ── Create Company B: Apex Global Tech ────────────────────────────────
        c_apex = Company(name="Apex Global Tech", code="APEX", contact_email="admin@apexglobal.com", status="Active")
        db.session.add(c_apex)
        db.session.flush()

        depts_b, fws_b, ctrls_b = seed_company_defaults(c_apex)
        sec_dept_b = depts_b[0]

        superadmin_b = User(
            company_id=c_apex.id, full_name="Apex SuperAdmin", username="apexadmin",
            email="superadmin@apexglobal.com", role="Super Admin",
            department_id=sec_dept_b.id, job_title="VP Security",
            phone="+1-555-0200", status="Active", must_change_password=False
        )
        superadmin_b.set_password("Admin@123")
        db.session.add(superadmin_b)
        db.session.commit()

        print("\n[OK] Multi-Company Database seeded successfully!")
        print("-" * 55)
        print("Company A: Acme Cybersecurity Corp")
        print("  Super Admin Email: superadmin@compliance.com | Password: Admin@123")
        print("Company B: Apex Global Tech")
        print("  Super Admin Email: superadmin@apexglobal.com | Password: Admin@123")
        print("-" * 55)


if __name__ == '__main__':
    seed()
