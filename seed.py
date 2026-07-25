"""
seed.py – Database seeding script
Run once after fresh installation: python seed.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime, timedelta
from app import app
from models import db, User, Department, Framework, Policy, Control, Task, Evidence, Audit, RiskAssessment, Notification, ActivityLog


def seed():
    with app.app_context():
        db.drop_all()
        db.create_all()
        print("Tables created.")

        # ── Departments ─────────────────────────────────────────────────────
        depts = [
            Department(name="Cybersecurity & Governance",   code="SEC-01", manager_name="Sarah Jenkins",  description="Oversees security, policies, audits, and risk."),
            Department(name="IT Infrastructure & Systems",   code="IT-01",  manager_name="David Miller",   description="Manages servers, cloud, networks, and endpoints."),
            Department(name="Software Engineering",          code="DEV-01", manager_name="Alex Turner",    description="Application development and Secure SDLC."),
            Department(name="Human Resources",               code="HR-01",  manager_name="Elena Rostova",  description="Employee onboarding, training, and compliance."),
            Department(name="Finance & Operations",          code="OPS-01", manager_name="Robert Chen",    description="Financial operations and regulatory reporting."),
        ]
        db.session.add_all(depts); db.session.commit()
        sec_dept = depts[0]; it_dept = depts[1]; dev_dept = depts[2]; hr_dept = depts[3]
        print("Departments seeded.")

        # ── Users ────────────────────────────────────────────────────────────
        superadmin = User(
            full_name="Super Administrator", username="superadmin",
            email="superadmin@compliance.com", role="Super Admin",
            department_id=sec_dept.id, job_title="Chief Information Security Officer",
            phone="+1-555-0100", status="Active",
            must_change_password=True   # force password change on first login
        )
        superadmin.set_password("Admin@123")

        admin = User(
            full_name="Sarah Jenkins", username="admin",
            email="admin@compliance.com", role="Admin",
            department_id=sec_dept.id, job_title="Security Compliance Manager",
            phone="+1-555-0101", status="Active", must_change_password=False
        )
        admin.set_password("password123")

        auditor = User(
            full_name="Michael Vance", username="auditor",
            email="auditor@compliance.com", role="Auditor",
            department_id=sec_dept.id, job_title="Lead Security Auditor",
            phone="+1-555-0102", status="Active", must_change_password=False
        )
        auditor.set_password("password123")

        emp1 = User(
            full_name="David Miller", username="employee",
            email="employee@compliance.com", role="Employee",
            department_id=it_dept.id, job_title="Systems Administrator",
            phone="+1-555-0103", status="Active", must_change_password=False
        )
        emp1.set_password("password123")

        emp2 = User(
            full_name="John Doe", username="john.doe",
            email="john.doe@company.com", role="Employee",
            department_id=dev_dept.id, job_title="Senior Software Engineer",
            phone="+1-555-0104", status="Active", must_change_password=False
        )
        emp2.set_password("password123")

        emp3 = User(
            full_name="Jane Smith", username="jane.smith",
            email="jane.smith@company.com", role="Employee",
            department_id=hr_dept.id, job_title="HR Operations Lead",
            phone="+1-555-0105", status="Active", must_change_password=False
        )
        emp3.set_password("password123")

        db.session.add_all([superadmin, admin, auditor, emp1, emp2, emp3])
        db.session.commit()
        print("Users seeded.")

        # ── Frameworks ──────────────────────────────────────────────────────
        fw_iso   = Framework(name="ISO/IEC 27001:2022",       code="ISO-27001",   version="2022", category="International Standard", status="Enabled",
                             description="International standard for ISMS, defining security controls across Annex A domains.")
        fw_nist  = Framework(name="NIST Cybersecurity Framework", code="NIST-CSF-2.0", version="2.0", category="Government Standard",   status="Enabled",
                             description="Framework for managing cybersecurity risk (Govern, Identify, Protect, Detect, Respond, Recover).")
        fw_pci   = Framework(name="PCI DSS v4.0",               code="PCI-DSS-4.0", version="4.0", category="Financial Security",      status="Enabled",
                             description="Payment Card Industry Data Security Standard for protecting cardholder data.")
        fw_hipaa = Framework(name="HIPAA Security Rule",         code="HIPAA-SEC",   version="2023", category="Healthcare Security",     status="Enabled",
                             description="Safeguards for electronic Protected Health Information (ePHI).")
        db.session.add_all([fw_iso, fw_nist, fw_pci, fw_hipaa]); db.session.commit()
        print("Frameworks seeded.")

        # ── Policies ────────────────────────────────────────────────────────
        policies = [
            Policy(title="Global Access Control & Identity Policy",     policy_code="POL-AC-01",     framework_id=fw_iso.id,   category="Access Control",       status="Active", created_by_id=admin.id,
                   description="Mandatory MFA, strong password policy (14+ chars), and zero-trust access control."),
            Policy(title="Data Cryptography & Key Management Policy",    policy_code="POL-CRYPTO-02", framework_id=fw_iso.id,   category="Data Security",        status="Active", created_by_id=admin.id,
                   description="AES-256 encryption at rest, TLS 1.3 in transit."),
            Policy(title="Incident Response & Breach Notification Policy",policy_code="POL-IR-03",    framework_id=fw_nist.id,  category="Incident Management",  status="Active", created_by_id=admin.id,
                   description="72-hour regulatory reporting; containment playbooks."),
            Policy(title="Cardholder Data Environment Protection Policy", policy_code="POL-PCI-04",   framework_id=fw_pci.id,   category="Cardholder Protection",status="Active", created_by_id=admin.id,
                   description="Network segmentation, tokenization, quarterly vulnerability scans."),
            Policy(title="ePHI Safeguards & Privacy Compliance Standard", policy_code="POL-HIPAA-05", framework_id=fw_hipaa.id, category="Healthcare Security",   status="Active", created_by_id=admin.id,
                   description="Technical, physical, and administrative safeguards for ePHI."),
        ]
        db.session.add_all(policies); db.session.commit()
        print("Policies seeded.")

        # ── Controls ────────────────────────────────────────────────────────
        c1 = Control(framework_id=fw_iso.id,  control_code="A.5.15",    name="Access Control & Password Policy",      category="Identity & Access",    risk_level="High",     status="Implemented",    description="Strong passwords and automatic session timeout.")
        c2 = Control(framework_id=fw_iso.id,  control_code="A.8.5",     name="Multi-Factor Authentication (MFA)",     category="Identity & Access",    risk_level="Critical",  status="Implemented",    description="MFA for all cloud services, VPNs, admin portals.")
        c3 = Control(framework_id=fw_iso.id,  control_code="A.8.7",     name="Antivirus & EDR Endpoint Protection",   category="Endpoint Protection",  risk_level="High",     status="Implemented",    description="Next-Gen EDR with automated virus definition updates.")
        c4 = Control(framework_id=fw_iso.id,  control_code="A.8.20",    name="Firewall & Network Security Config",    category="Network Security",     risk_level="High",     status="Implemented",    description="Restrictive firewall rules and IDS/IPS systems.")
        c5 = Control(framework_id=fw_iso.id,  control_code="A.8.24",    name="Full Disk Encryption (BitLocker)",      category="Data Protection",      risk_level="Critical",  status="Implemented",    description="AES-256 encryption on all laptops and mobile devices.")
        c6 = Control(framework_id=fw_nist.id, control_code="PR.IP-01",  name="OS & Vulnerability Patching",          category="System Maintenance",   risk_level="High",     status="Partial",        description="Apply critical patches within 14 days of publication.")
        c7 = Control(framework_id=fw_nist.id, control_code="PR.IP-04",  name="Automated Backup & Disaster Recovery",  category="Resilience",           risk_level="High",     status="Implemented",    description="Encrypted daily off-site backups; quarterly recovery tests.")
        c8 = Control(framework_id=fw_hipaa.id,control_code="§ 164.308", name="Security Awareness & Phishing Training",category="Personnel",            risk_level="Medium",    status="Partial",        description="Mandatory quarterly cybersecurity awareness training.")
        db.session.add_all([c1,c2,c3,c4,c5,c6,c7,c8]); db.session.commit()
        print("Controls seeded.")

        # ── Tasks ────────────────────────────────────────────────────────────
        today = datetime.utcnow().date()
        t1 = Task(title="Verify MFA Enforcement on All Corporate Portals",    control_id=c2.id, assigned_to_id=emp1.id, assigned_by_id=admin.id, priority="Critical", due_date=today+timedelta(5),  status="Completed", completed_at=datetime.utcnow()-timedelta(1),
                  description="Confirm 100% MFA enrollment in Azure AD / Google Workspace.")
        t2 = Task(title="Deploy Q3 Windows Server & Linux Security Patches",   control_id=c6.id, assigned_to_id=emp1.id, assigned_by_id=admin.id, priority="High",     due_date=today+timedelta(3),  status="Under Review",
                  description="Apply vendor security patches across production hosts.")
        t3 = Task(title="Audit BitLocker Full Disk Encryption Status",         control_id=c5.id, assigned_to_id=emp1.id, assigned_by_id=admin.id, priority="High",     due_date=today+timedelta(10), status="In Progress",
                  description="Export endpoint management log confirming disk encryption on company laptops.")
        t4 = Task(title="Submit Q3 Security Awareness Training Certificates",  control_id=c8.id, assigned_to_id=emp1.id, assigned_by_id=admin.id, priority="Medium",   due_date=today-timedelta(2),  status="Overdue",
                  description="Ensure all staff complete the annual phishing awareness module.")
        db.session.add_all([t1,t2,t3,t4]); db.session.commit()
        print("Tasks seeded.")

        # ── Evidence ─────────────────────────────────────────────────────────
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        e1 = Evidence(task_id=t1.id, employee_id=emp1.id, file_path="uploads/mfa_report.pdf",         file_name="mfa_report.pdf",         file_type="application/pdf",  file_size=2048500, review_status="Approved",  reviewer_id=auditor.id, reviewer_comments="MFA report verified – 100% active.", uploaded_at=datetime.utcnow()-timedelta(1), reviewed_at=datetime.utcnow())
        e2 = Evidence(task_id=t2.id, employee_id=emp1.id, file_path="uploads/patch_log.docx",         file_name="patch_log.docx",         file_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", file_size=1048500, review_status="Pending",   uploaded_at=datetime.utcnow()-timedelta(hours=4))
        db.session.add_all([e1,e2]); db.session.commit()
        print("Evidence seeded.")

        # ── Audits ───────────────────────────────────────────────────────────
        a1 = Audit(name="Annual ISO 27001 Surveillance Audit Q3", audit_code="AUD-ISO-2026-01", framework_id=fw_iso.id,  auditor_id=auditor.id, start_date=today-timedelta(10), end_date=today+timedelta(5),  scope="All corporate infrastructure, cloud, and remote endpoints.",
                   status="In Progress", findings="Access controls strictly followed. Patch management SLA needs improvement.", recommendations="Automate OS patching; enforce zero-trust posture.", final_status="Partially Compliant")
        a2 = Audit(name="PCI DSS v4.0 Cardholder Env Audit",     audit_code="AUD-PCI-2026-02", framework_id=fw_pci.id,  auditor_id=auditor.id, start_date=today+timedelta(20), end_date=today+timedelta(30), scope="Payment gateway API and tokenization servers.",
                   status="Scheduled", final_status="Pending")
        db.session.add_all([a1,a2]); db.session.commit()
        print("Audits seeded.")

        # ── Risk Assessments ─────────────────────────────────────────────────
        risks = [
            RiskAssessment(title="Unpatched Endpoint OS Vulnerabilities",    control_id=c6.id, asset_scope="Corporate Workstations & Servers",  likelihood=4, impact=4, risk_score=16, risk_level="High",     assessed_by_id=admin.id, mitigations="Deploy automated WSUS; restrict local admin."),
            RiskAssessment(title="Phishing & Credential Harvester Exposure",  control_id=c8.id, asset_scope="All Personnel",                      likelihood=4, impact=5, risk_score=20, risk_level="Critical", assessed_by_id=admin.id, mitigations="FIDO2 Security Keys + mandatory phishing drills."),
            RiskAssessment(title="Unencrypted Portable USB Devices",          control_id=c5.id, asset_scope="Removable USB Storage",               likelihood=2, impact=3, risk_score=6,  risk_level="Medium",   assessed_by_id=admin.id, mitigations="Group policy USB block + BitLocker To Go."),
            RiskAssessment(title="Single Point of Failure in Cloud Firewall", control_id=c4.id, asset_scope="AWS Cloud Transit Gateway",           likelihood=1, impact=4, risk_score=4,  risk_level="Low",      assessed_by_id=admin.id, mitigations="Multi-AZ redundant gateways with failover."),
        ]
        db.session.add_all(risks); db.session.commit()
        print("Risk Assessments seeded.")

        # ── Notifications ────────────────────────────────────────────────────
        notifs = [
            Notification(user_id=emp1.id,    title="Overdue Task",       message="'Submit Q3 Security Awareness Training Certificates' is overdue.", type="danger",  link="/tasks"),
            Notification(user_id=admin.id,   title="Evidence Uploaded",  message="Employee submitted evidence for patch task. Review required.",       type="info",    link="/evidence"),
            Notification(user_id=auditor.id, title="Audit Active",       message="ISO 27001 Surveillance Audit Q3 is currently In Progress.",          type="warning", link="/audits"),
        ]
        db.session.add_all(notifs); db.session.commit()
        print("Notifications seeded.")

        # ── Activity Logs ────────────────────────────────────────────────────
        logs = [
            ActivityLog(user_name="admin@compliance.com",      user_role="Admin",       action="Policy Created",   details="POL-AC-01 Global Access Control Policy created.", ip_address="127.0.0.1"),
            ActivityLog(user_name="employee@compliance.com",   user_role="Employee",    action="Evidence Uploaded",details="Uploaded mfa_report.pdf for task MFA Verification.", ip_address="127.0.0.1"),
            ActivityLog(user_name="auditor@compliance.com",    user_role="Auditor",     action="Evidence Approved",details="Evidence #1 approved with reviewer comments.", ip_address="127.0.0.1"),
            ActivityLog(user_name="superadmin@compliance.com", user_role="Super Admin", action="System Init",      details="Default Super Admin account created on first run.", ip_address="127.0.0.1"),
        ]
        db.session.add_all(logs); db.session.commit()
        print("Activity logs seeded.")

        print("\n[OK] Database seeded successfully!")
        print("-" * 45)
        print("Default Super Admin:")
        print("  Email   : superadmin@compliance.com")
        print("  Password: Admin@123")
        print("  NOTE: Password change required on first login!")
        print("-" * 45)


if __name__ == '__main__':
    seed()
