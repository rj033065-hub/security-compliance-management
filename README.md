# 🛡️ Security Compliance Management System

A modern **Security Compliance Management System** built using **Flask** and **MySQL** to help organisations manage security policies, compliance frameworks, audits, risk assessments, and evidence in one centralized platform.

## 📌 Overview

This application enables organisations to monitor and manage compliance with industry standards such as **ISO/IEC 27001**, **NIST Cybersecurity Framework**, **PCI DSS**, and **HIPAA**. It provides role-based access, compliance tracking, audit management, risk assessment, evidence collection, and reporting through an intuitive web dashboard.

---

## ✨ Features

### 🔐 Authentication & Role-Based Access Control

* Secure login system
* Password hashing
* Role-Based Access Control (RBAC)
* Separate dashboards for:

  * Super Admin
  * Admin
  * Auditor
  * Employee

### 👑 Super Admin

* Manage all users
* Assign roles
* Manage departments
* Manage compliance frameworks
* View system-wide reports
* Monitor activity logs

### 🧑‍💼 Admin

* Manage employees
* Create and assign compliance tasks
* Manage policies
* Review evidence
* Generate reports

### 📝 Auditor

* Review submitted evidence
* Conduct audits
* Record findings
* Approve or reject compliance submissions
* Generate audit reports

### 👨‍💻 Employee

* View assigned tasks
* Upload compliance evidence
* Track compliance status
* Update profile

---

## 🛡️ Compliance Frameworks

Supports:

* ISO/IEC 27001
* NIST Cybersecurity Framework
* PCI DSS
* HIPAA

---

## 📋 Modules

* User Management
* Department Management
* Compliance Framework Management
* Policy Management
* Security Controls
* Task Assignment
* Evidence Management
* Audit Management
* Risk Assessment
* Notifications
* Activity Logs
* PDF Report Generation
* Excel Report Export

---

## 📊 Dashboard

The dashboard displays:

* Total Users
* Total Departments
* Compliance Score
* Active Policies
* Pending Tasks
* Completed Tasks
* Overdue Tasks
* Active Audits
* Risk Summary
* Recent Activities

---

## 🏗️ Technology Stack

### Frontend

* HTML5
* CSS3
* JavaScript
* Bootstrap 5
* Chart.js

### Backend

* Python
* Flask
* Flask-Login
* Flask-SQLAlchemy

### Database

* MySQL

### Reporting

* ReportLab
* openpyxl

### Security

* Password Hashing
* Session Management
* Role-Based Access Control
* Input Validation

---

## 📂 Project Structure

```text
security-compliance-management/
│
├── app.py
├── config.py
├── models.py
├── routes.py
├── seed.py
├── requirements.txt
│
├── templates/
├── static/
├── uploads/
├── reports/
│
└── README.md
```

---

## 🚀 Installation

### Clone the Repository

```bash
git clone https://github.com/your-username/security-compliance-management.git
cd security-compliance-management
```

### Create a Virtual Environment

```bash
python -m venv venv
```

### Activate the Environment

**Windows**

```bash
venv\Scripts\activate
```

**Linux / macOS**

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure the Database

Update your MySQL connection details in the project configuration.

### Seed the Database

```bash
python seed.py
```

### Run the Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## 👤 Default Login

### Super Admin

Email

```text
superadmin@compliance.com
```

Password

```text
Admin@123
```

The application requires the Super Admin to change the default password after the first login.

---

## 🔒 Security Features

* Password hashing
* Secure authentication
* Role-Based Access Control (RBAC)
* Session management
* Activity logging
* Evidence tracking
* Audit trail

---

## 📈 Future Enhancements

* AI Compliance Assistant
* Email notifications
* Two-Factor Authentication (2FA)
* REST API
* Cloud storage integration
* Advanced analytics
* Multi-organisation support

---

## 🎓 Academic Purpose

This project was developed as a cybersecurity academic project to demonstrate secure web application development, compliance management, audit workflows, and role-based access control using Flask and MySQL.

---

## 👨‍💻 Author

**Raj Jadhav**

Cybersecurity Enthusiast | Python Developer | Flask Developer

GitHub: https://github.com/rj033065

LinkedIn: https://www.linkedin.com/in/raj-jadhav-b8b449378?utm_source=share_via&utm_content=profile&utm_medium=member_android

---

## 📄 License

This project is intended for educational and demonstration purposes.
