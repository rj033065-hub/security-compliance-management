import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db
from models import User, Department


@pytest.fixture
def client():
    app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI='sqlite:///:memory:')
    with app.app_context():
        db.drop_all()
        db.create_all()
        dept = Department(name='IT', code='IT01', description='IT Department')
        db.session.add(dept)
        db.session.commit()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def test_login_redirects_to_dashboard_for_active_user(client):
    user = User(full_name='Test User', username='testuser', email='test@example.com', role='Employee', department_id=1, status='Active')
    user.set_password('Password123')
    db.session.add(user)
    db.session.commit()

    response = client.post('/login', data={'username': 'test@example.com', 'password': 'Password123'}, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/dashboard')


def test_admin_cannot_access_super_admin_only_route(client):
    admin = User(full_name='Admin User', username='admin', email='admin@example.com', role='Admin', department_id=1, status='Active')
    admin.set_password('Password123')
    db.session.add(admin)
    db.session.commit()

    client.post('/login', data={'username': 'admin@example.com', 'password': 'Password123'}, follow_redirects=False)
    response = client.get('/logs', follow_redirects=False)
    assert response.status_code == 302
