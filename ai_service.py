import json
import random

class AIConsultant:
    @staticmethod
    def answer_query(query, role='Admin'):
        query_lower = query.lower()
        
        if 'iso' in query_lower or '27001' in query_lower:
            return {
                "answer": "ISO/IEC 27001:2022 emphasizes Information Security Management Systems (ISMS). Key controls include Clause 5 (Leadership), Annex A.5 (Organizational Controls), Annex A.6 (People Controls), Annex A.7 (Physical Controls), and Annex A.8 (Technological Controls). We recommend uploading policy evidence for MFA, encryption, and quarterly access reviews.",
                "confidence": 0.96,
                "suggested_actions": ["Review Annex A.8 Technological Controls", "Schedule Internal ISMS Audit", "Assign Employee Awareness Tasks"]
            }
        elif 'nist' in query_lower or 'csf' in query_lower:
            return {
                "answer": "The NIST Cybersecurity Framework consists of 6 core functions: GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, and RECOVER. For compliance alignment, prioritize asset management (ID.AM), identity management (PR.AA), and continuous monitoring (DE.CM).",
                "confidence": 0.94,
                "suggested_actions": ["Assess ID.AM-01 Asset Inventory", "Check PR.AA Multi-Factor Authentication", "Verify Incident Response Playbooks"]
            }
        elif 'pci' in query_lower or 'pci-dss' in query_lower or 'credit card' in query_lower:
            return {
                "answer": "PCI DSS v4.0 requires 12 principal requirements ranging from maintaining secure firewalls to encrypting cardholder data in transit and at rest. Ensure strict scope isolation (tokenize CHD), mandatory MFA for all CDE access, and automated log analysis.",
                "confidence": 0.98,
                "suggested_actions": ["Validate Requirement 3: Protect Stored Account Data", "Enforce Requirement 8: Identification & Authentication", "Run Quarterly Vulnerability Scans"]
            }
        elif 'hipaa' in query_lower or 'health' in query_lower or 'phi' in query_lower:
            return {
                "answer": "HIPAA Compliance mandates the Security Rule (Administrative, Physical, and Technical Safeguards) and Privacy Rule. Ensure electronic Protected Health Information (ePHI) is encrypted with AES-256 both in transit and at rest, and maintain immutable audit logs for 6 years.",
                "confidence": 0.95,
                "suggested_actions": ["Audit Technical Safeguards § 164.312", "Conduct Business Associate Agreement (BAA) Review", "Verify ePHI Disk Encryption"]
            }
        elif 'evidence' in query_lower or 'upload' in query_lower:
            return {
                "answer": "Valid compliance evidence must be: 1) Authentic (signed/exported directly from system), 2) Timely (within the current audit cycle window), and 3) Verifiable (showing explicit settings like BitLocker active status, AV signature date, or log screenshot with hostnames).",
                "confidence": 0.92,
                "suggested_actions": ["Upload PDF/PNG export of active AV agent status", "Attach system configuration policy document", "Submit employee awareness completion certificates"]
            }
        elif 'risk' in query_lower or 'heatmap' in query_lower or 'assessment' in query_lower:
            return {
                "answer": "Risk level is calculated as Likelihood (1-5) x Impact (1-5). Items scoring 20-25 are Critical and require immediate CISO/Admin escalation with a 7-day remediation SLA. High risks (13-19) require compensation controls within 30 days.",
                "confidence": 0.97,
                "suggested_actions": ["Filter Risk Heatmap by Critical", "Assign task for unmitigated High Risk controls", "Generate AI Risk Executive Summary"]
            }
        else:
            return {
                "answer": f"AI Security Assistant analysis for '{query}': Based on your current Security Compliance posture, we recommend maintaining active control validation across all frameworks, ensuring employee task completion rates exceed 90%, and keeping audit logs tamper-evident.",
                "confidence": 0.89,
                "suggested_actions": ["Review Policy Management Catalogue", "Check Pending Task Queue", "Download Departmental Compliance Report"]
            }

    @staticmethod
    def recommend_policies(framework_name):
        recommendations = [
            {
                "title": f"{framework_name} Information Security Policy & Governance",
                "category": "Governance & Management",
                "summary": "Defines executive security commitment, roles, responsibilities, and ISMS steering committee oversight.",
                "priority": "High"
            },
            {
                "title": f"{framework_name} Access Control & Identity Management Policy",
                "category": "Access Control",
                "summary": "Mandates Principle of Least Privilege, Role-Based Access Control (RBAC), quarterly access certifications, and MFA.",
                "priority": "Critical"
            },
            {
                "title": f"{framework_name} Incident Response & Business Continuity Policy",
                "category": "Incident Response",
                "summary": "Establishes incident triage escalation paths, reporting timeframes (72 hrs), and annual table-top exercises.",
                "priority": "High"
            },
            {
                "title": f"{framework_name} Cryptography & Key Management Standard",
                "category": "Data Protection",
                "summary": "Enforces AES-256 for data at rest, TLS 1.3 for data in transit, and hardware security module key rotation cycles.",
                "priority": "Medium"
            }
        ]
        return recommendations

    @staticmethod
    def analyze_missing_controls(controls):
        missing = []
        for ctrl in controls:
            if ctrl.status == 'Not Implemented' or ctrl.status == 'Partial':
                missing.append({
                    "code": ctrl.control_code,
                    "name": ctrl.name,
                    "risk_level": ctrl.risk_level,
                    "recommendation": f"Implement '{ctrl.name}' to address potential compliance gaps under {ctrl.framework.name if ctrl.framework else 'standard framework'}.",
                    "suggested_task": f"Setup and verify {ctrl.name} across company endpoints and cloud servers."
                })
        return missing

    @staticmethod
    def generate_executive_risk_summary(high_risk_controls, audit_count, open_tasks):
        summary = (
            f"AI Risk Assessment Digest: Currently identifying {len(high_risk_controls)} High/Critical risk security controls requiring remediation. "
            f"There are {open_tasks} open compliance tasks awaiting employee action or auditor review across {audit_count} scheduled/active audits. "
            f"Primary focus areas: Enforce MFA everywhere, patch high-severity OS vulnerabilities, and verify daily backup restoration drills."
        )
        return summary
