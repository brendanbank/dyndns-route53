import base64
import bcrypt
import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import (
    TEST_PASSWORD, ADMIN_PASSWORD, login_user_full, _hash_password,
)


# ==============================================================================
# Authentication
# ==============================================================================

class TestAuthentication:

    def test_login_page_loads(self, client):
        resp = client.get('/admin/login')
        assert resp.status_code == 200
        assert b'Log In' in resp.data

    def test_valid_login_redirects_to_totp_setup(self, client, admin_user):
        resp = client.post('/admin/login', data={
            'username': 'admin', 'password': ADMIN_PASSWORD,
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert 'totp-setup' in resp.headers['Location']

    def test_valid_login_redirects_to_totp_verify(self, client, admin_user, admin_with_totp):
        resp = client.post('/admin/login', data={
            'username': 'admin', 'password': ADMIN_PASSWORD,
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert 'totp-verify' in resp.headers['Location']

    def test_invalid_password_rejected(self, client, admin_user):
        resp = client.post('/admin/login', data={
            'username': 'admin', 'password': 'wrongpassword',
        }, follow_redirects=True)
        assert b'Invalid username or password' in resp.data

    def test_nonexistent_user_rejected(self, client):
        resp = client.post('/admin/login', data={
            'username': 'ghost', 'password': 'whatever',
        }, follow_redirects=True)
        assert b'Invalid username or password' in resp.data

    def test_inactive_user_rejected(self, client, inactive_user):
        resp = client.post('/admin/login', data={
            'username': 'inactive', 'password': TEST_PASSWORD,
        }, follow_redirects=True)
        assert b'Invalid username or password' in resp.data

    def test_web_login_disabled_user_rejected(self, client, app):
        """User with web_login=False cannot log in to the web UI."""
        from models import db, User
        from tests.conftest import _hash_password
        with app.app_context():
            user = User(
                username='apionly',
                password_hash=_hash_password(TEST_PASSWORD),
                role='user',
                is_active=True,
                web_login=False,
            )
            db.session.add(user)
            db.session.commit()
        resp = client.post('/admin/login', data={
            'username': 'apionly', 'password': TEST_PASSWORD,
        }, follow_redirects=True)
        assert b'Web login is not enabled for this account.' in resp.data
        # Should NOT redirect to TOTP setup/verify
        assert b'totp' not in resp.data.lower() or b'Log In' in resp.data

    def test_web_login_disabled_user_can_use_api(self, client, app):
        """User with web_login=False can still use /nic/update via HTTP Basic Auth."""
        import base64
        from models import db, User, Domain, Hostname
        from tests.conftest import _hash_password
        with app.app_context():
            user = User(
                username='apionly',
                password_hash=_hash_password(TEST_PASSWORD),
                role='user',
                is_active=True,
                web_login=False,
            )
            db.session.add(user)
            db.session.commit()
            domain = Domain(name='api.example.com')
            db.session.add(domain)
            db.session.commit()
            hn = Hostname(name='test.api.example.com', domain_id=domain.id, user_id=user.id)
            db.session.add(hn)
            db.session.commit()
        creds = base64.b64encode(b'apionly:' + TEST_PASSWORD.encode()).decode()
        headers = {'Authorization': f'Basic {creds}'}
        resp = client.get('/nic/update?hostname=test.api.example.com&myip=1.2.3.4', headers=headers)
        # Should authenticate successfully — 911 because no backend configured, not badauth
        assert b'badauth' not in resp.data
        assert b'911' in resp.data

    def test_full_totp_setup_flow(self, client, admin_user):
        resp = login_user_full(client, 'admin', ADMIN_PASSWORD)
        assert resp.status_code == 200
        assert b'Dashboard' in resp.data or b'dashboard' in resp.data.lower()

    def test_full_totp_verify_flow(self, client, admin_user, admin_with_totp):
        resp = login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        assert resp.status_code == 200
        assert b'Dashboard' in resp.data or b'dashboard' in resp.data.lower()

    def test_invalid_totp_code_rejected(self, client, admin_user, admin_with_totp):
        client.post('/admin/login', data={
            'username': 'admin', 'password': ADMIN_PASSWORD,
        })
        resp = client.post('/admin/totp-verify', data={'code': '000000'}, follow_redirects=True)
        assert b'Invalid authentication code' in resp.data

    def test_totp_verify_without_pending_session(self, client):
        resp = client.get('/admin/totp-verify', follow_redirects=False)
        assert resp.status_code == 302
        assert 'login' in resp.headers['Location']

    def test_totp_setup_without_pending_session(self, client):
        resp = client.get('/admin/totp-setup', follow_redirects=False)
        assert resp.status_code == 302
        assert 'login' in resp.headers['Location']

    def test_logout_clears_session(self, client, admin_user):
        login_user_full(client, 'admin', ADMIN_PASSWORD)
        resp = client.get('/admin/logout', follow_redirects=False)
        assert resp.status_code == 302
        # After logout, dashboard should redirect to login
        resp = client.get('/admin/', follow_redirects=False)
        assert resp.status_code == 302
        assert 'login' in resp.headers['Location']


# ==============================================================================
# Authorization
# ==============================================================================

class TestAuthorization:

    def test_unauthenticated_redirects_to_login(self, client):
        resp = client.get('/admin/', follow_redirects=False)
        assert resp.status_code == 302
        assert 'login' in resp.headers['Location']

    def test_regular_user_cannot_access_user_list(self, client, regular_user, regular_user_with_totp):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get('/admin/users', follow_redirects=False)
        assert resp.status_code == 302
        assert 'login' in resp.headers['Location']

    def test_regular_user_cannot_create_users(self, client, regular_user, regular_user_with_totp):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get('/admin/users/new', follow_redirects=False)
        assert resp.status_code == 302

    def test_admin_can_access_user_list(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.get('/admin/users')
        assert resp.status_code == 200

    def test_admin_can_access_dashboard(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.get('/admin/')
        assert resp.status_code == 200

    def test_regular_user_can_access_dashboard(self, client, regular_user, regular_user_with_totp):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get('/admin/')
        assert resp.status_code == 200

    def test_regular_user_can_access_events(self, client, regular_user, regular_user_with_totp):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get('/admin/events')
        assert resp.status_code == 200

    def test_regular_user_can_access_profile(self, client, regular_user, regular_user_with_totp):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get('/admin/profile')
        assert resp.status_code == 200

    def test_regular_user_cannot_access_domains(self, client, regular_user, regular_user_with_totp):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get('/admin/domains', follow_redirects=False)
        assert resp.status_code == 302
        assert 'login' in resp.headers['Location']

    def test_regular_user_can_access_hostnames(self, client, regular_user, regular_user_with_totp):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get('/admin/hostnames')
        assert resp.status_code == 200


# ==============================================================================
# User Management (Admin)
# ==============================================================================

class TestUserManagement:

    def _login_admin(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)

    def test_create_user(self, client, admin_user, admin_with_totp, app):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post('/admin/users/new', data={
            'username': 'newuser',
            'password': 'newpass12345',
            'role': 'user',
            'is_active': 'y',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'created' in resp.data.lower() or b'newuser' in resp.data
        # Default web_login should be False
        from models import User
        with app.app_context():
            u = User.query.filter_by(username='newuser').first()
            assert u is not None
            assert u.web_login is False

    def test_create_user_with_web_login(self, client, admin_user, admin_with_totp, app):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post('/admin/users/new', data={
            'username': 'webuser',
            'password': 'newpass12345',
            'role': 'user',
            'is_active': 'y',
            'web_login': 'y',
        }, follow_redirects=True)
        assert resp.status_code == 200
        from models import User
        with app.app_context():
            u = User.query.filter_by(username='webuser').first()
            assert u is not None
            assert u.web_login is True

    def test_edit_user(self, client, admin_user, admin_with_totp, regular_user, app):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}', data={
            'username': 'testuser_renamed',
            'password': '',
            'role': 'user',
            'is_active': 'y',
            'web_login': 'y',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'updated' in resp.data.lower() or b'testuser_renamed' in resp.data

    def test_delete_user(self, client, admin_user, admin_with_totp, regular_user):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}/delete', follow_redirects=True)
        assert resp.status_code == 200
        assert b'deleted' in resp.data.lower()

    def test_cannot_delete_self(self, client, admin_user, admin_with_totp):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/users/{admin_user}/delete', follow_redirects=True)
        assert b'cannot delete your own' in resp.data.lower()

    def test_duplicate_username_rejected(self, client, admin_user, admin_with_totp, regular_user):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post('/admin/users/new', data={
            'username': 'testuser',
            'password': 'somepass12345',
            'role': 'user',
            'is_active': 'y',
        }, follow_redirects=True)
        assert b'already exists' in resp.data.lower()


# ==============================================================================
# TOTP Management
# ==============================================================================

class TestTOTPManagement:

    def test_admin_reset_user_2fa(self, client, admin_user, admin_with_totp, regular_user, regular_user_with_totp, app):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}/reset-2fa', follow_redirects=True)
        assert b'reset' in resp.data.lower()
        # Verify TOTP was actually cleared
        from models import User
        with app.app_context():
            user = User.query.get(regular_user)
            assert user.totp_secret is None

    def test_self_reset_2fa_correct_password(self, client, admin_user, admin_with_totp, app):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post('/admin/profile/reset-2fa', data={
            'current_password': ADMIN_PASSWORD,
        }, follow_redirects=True)
        assert b'reset' in resp.data.lower()

    def test_self_reset_2fa_wrong_password(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post('/admin/profile/reset-2fa', data={
            'current_password': 'wrongpass',
        }, follow_redirects=True)
        assert b'incorrect' in resp.data.lower()


# ==============================================================================
# Profile / Password Change
# ==============================================================================

class TestProfile:

    def test_password_change_success(self, client, admin_user, admin_with_totp, app):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post('/admin/profile', data={
            'current_password': ADMIN_PASSWORD,
            'new_password': 'newadminpass1',
            'confirm_password': 'newadminpass1',
        }, follow_redirects=True)
        assert b'changed' in resp.data.lower() or b'success' in resp.data.lower()
        # Verify new password works
        from models import User
        with app.app_context():
            user = User.query.get(admin_user)
            assert bcrypt.checkpw(b'newadminpass1', user.password_hash.encode())

    def test_password_change_wrong_current(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post('/admin/profile', data={
            'current_password': 'wrongpassword',
            'new_password': 'newpass12345',
            'confirm_password': 'newpass12345',
        }, follow_redirects=True)
        assert b'incorrect' in resp.data.lower()

    def test_password_change_mismatch_confirm(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post('/admin/profile', data={
            'current_password': ADMIN_PASSWORD,
            'new_password': 'newpass12345',
            'confirm_password': 'different123',
        }, follow_redirects=True)
        assert b'do not match' in resp.data.lower() or b'match' in resp.data.lower()


# ==============================================================================
# DynDNS API (/nic/update)
# ==============================================================================

class TestDynDNSAPI:

    def _basic_auth_header(self, username, password):
        creds = base64.b64encode(f'{username}:{password}'.encode()).decode()
        return {'Authorization': f'Basic {creds}'}

    def test_no_auth_returns_badauth(self, client):
        resp = client.get('/nic/update?hostname=test.example.com&myip=1.2.3.4')
        assert resp.status_code == 200
        assert b'badauth' in resp.data

    def test_bad_auth_returns_badauth(self, client, admin_user):
        headers = self._basic_auth_header('admin', 'wrongpass')
        resp = client.get('/nic/update?hostname=test.example.com&myip=1.2.3.4', headers=headers)
        assert b'badauth' in resp.data

    def test_missing_hostname_returns_911(self, client, admin_user):
        headers = self._basic_auth_header('admin', ADMIN_PASSWORD)
        resp = client.get('/nic/update?myip=1.2.3.4', headers=headers)
        assert b'911' in resp.data

    def test_no_matching_hostname_returns_nohost(self, client, admin_user):
        headers = self._basic_auth_header('admin', ADMIN_PASSWORD)
        resp = client.get('/nic/update?hostname=test.example.com&myip=1.2.3.4', headers=headers)
        assert b'nohost' in resp.data

    def test_invalid_hostname_returns_notfqdn(self, client, admin_user):
        headers = self._basic_auth_header('admin', ADMIN_PASSWORD)
        resp = client.get('/nic/update?hostname=-invalid..host&myip=1.2.3.4', headers=headers)
        assert b'notfqdn' in resp.data

    def test_query_param_auth_works(self, client, admin_user):
        resp = client.get(
            f'/nic/update?username=admin&password={ADMIN_PASSWORD}'
            f'&hostname=test.example.com&myip=1.2.3.4'
        )
        # Should authenticate successfully — nohost because no hostname registered
        assert b'nohost' in resp.data

    def test_inactive_user_badauth(self, client, inactive_user):
        headers = self._basic_auth_header('inactive', TEST_PASSWORD)
        resp = client.get('/nic/update?hostname=test.example.com&myip=1.2.3.4', headers=headers)
        assert b'badauth' in resp.data

    def test_no_totp_required_for_api(self, client, admin_user):
        """DynDNS API uses HTTP Basic Auth only — no TOTP needed."""
        headers = self._basic_auth_header('admin', ADMIN_PASSWORD)
        resp = client.get('/nic/update?hostname=test.example.com&myip=1.2.3.4', headers=headers)
        # Should get through auth (nohost because no hostname registered, not badauth)
        assert b'badauth' not in resp.data

    def test_registered_hostname_no_backend_returns_911(self, client, regular_user, test_domain, test_hostname):
        """Hostname exists but domain has no backends -> 911."""
        headers = self._basic_auth_header('testuser', TEST_PASSWORD)
        resp = client.get('/nic/update?hostname=test.example.com&myip=1.2.3.4', headers=headers)
        assert b'911' in resp.data

    def test_updatetype_param_ignored(self, client, admin_user):
        """updatetype parameter is accepted but ignored."""
        headers = self._basic_auth_header('admin', ADMIN_PASSWORD)
        resp = client.get('/nic/update?hostname=test.example.com&myip=1.2.3.4&updatetype=nsupdate', headers=headers)
        # Should still get nohost (no hostname registered), not an error about bad updatetype
        assert b'nohost' in resp.data


# ==============================================================================
# DynDNS Delete API (/nic/delete)
# ==============================================================================

class TestDynDNSDeleteAPI:

    def _basic_auth_header(self, username, password):
        creds = base64.b64encode(f'{username}:{password}'.encode()).decode()
        return {'Authorization': f'Basic {creds}'}

    def test_delete_no_auth_returns_badauth(self, client):
        resp = client.get('/nic/delete?hostname=test.example.com')
        assert resp.status_code == 200
        assert b'badauth' in resp.data

    def test_delete_unregistered_hostname_returns_nohost(self, client, admin_user):
        headers = self._basic_auth_header('admin', ADMIN_PASSWORD)
        resp = client.get('/nic/delete?hostname=test.example.com', headers=headers)
        assert b'nohost' in resp.data

    def test_delete_invalid_hostname_returns_notfqdn(self, client, admin_user):
        headers = self._basic_auth_header('admin', ADMIN_PASSWORD)
        resp = client.get('/nic/delete?hostname=-invalid..host', headers=headers)
        assert b'notfqdn' in resp.data

    def test_delete_registered_hostname_no_backend_returns_911(self, client, regular_user, test_domain, test_hostname):
        """Hostname exists but domain has no backends -> 911."""
        headers = self._basic_auth_header('testuser', TEST_PASSWORD)
        resp = client.get('/nic/delete?hostname=test.example.com', headers=headers)
        assert b'911' in resp.data

    def test_delete_missing_hostname_returns_911(self, client, admin_user):
        headers = self._basic_auth_header('admin', ADMIN_PASSWORD)
        resp = client.get('/nic/delete', headers=headers)
        assert b'911' in resp.data

    def test_delete_with_invalid_myip_returns_911(self, client, admin_user):
        headers = self._basic_auth_header('admin', ADMIN_PASSWORD)
        resp = client.get('/nic/delete?hostname=test.example.com&myip=notanip', headers=headers)
        assert b'911' in resp.data

    def test_delete_creates_event(self, client, admin_user, app):
        headers = {'Authorization': 'Basic ' + base64.b64encode(b'admin:' + ADMIN_PASSWORD.encode()).decode()}
        client.get('/nic/delete?hostname=test.example.com', headers=headers)
        from models import Event
        with app.app_context():
            events = Event.query.filter_by(event_type='dns_delete').all()
            assert len(events) >= 1
            assert events[0].username == 'admin'


# ==============================================================================
# Events
# ==============================================================================

class TestEvents:

    def test_event_page_loads(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.get('/admin/events')
        assert resp.status_code == 200

    def test_api_call_creates_event(self, client, admin_user, app):
        headers = {'Authorization': 'Basic ' + base64.b64encode(b'admin:' + ADMIN_PASSWORD.encode()).decode()}
        client.get('/nic/update?hostname=test.example.com&myip=1.2.3.4', headers=headers)
        from models import Event
        with app.app_context():
            events = Event.query.all()
            assert len(events) >= 1
            assert events[0].username == 'admin'


# ==============================================================================
# Domain Management (Admin)
# ==============================================================================

class TestDomainManagement:

    def _login_admin(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)

    def test_domain_list_page_loads(self, client, admin_user, admin_with_totp):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.get('/admin/domains')
        assert resp.status_code == 200

    def test_create_domain(self, client, admin_user, admin_with_totp, app):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post('/admin/domains', data={
            'name': 'dyn.example.com',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'dyn.example.com' in resp.data
        from models import Domain
        with app.app_context():
            d = Domain.query.filter_by(name='dyn.example.com').first()
            assert d is not None

    def test_duplicate_domain_rejected(self, client, admin_user, admin_with_totp, test_domain):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post('/admin/domains', data={
            'name': 'example.com',
        }, follow_redirects=True)
        assert b'already exists' in resp.data.lower()

    def test_edit_domain(self, client, admin_user, admin_with_totp, test_domain):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/domains/{test_domain}', data={
            'name': 'updated.example.com',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'updated' in resp.data.lower()

    def test_delete_domain(self, client, admin_user, admin_with_totp, test_domain):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/domains/{test_domain}/delete', follow_redirects=True)
        assert b'deleted' in resp.data.lower()

    def test_add_backend_to_domain(self, client, admin_user, admin_with_totp, test_domain, app):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/domains/{test_domain}/backends/new', data={
            'backend_type': 'aws',
        }, follow_redirects=True)
        assert resp.status_code == 200
        from models import DomainBackend
        with app.app_context():
            b = DomainBackend.query.filter_by(domain_id=test_domain, backend_type='aws').first()
            assert b is not None

    def test_duplicate_backend_rejected(self, client, admin_user, admin_with_totp, test_domain, test_domain_with_backend):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/domains/{test_domain}/backends/new', data={
            'backend_type': 'aws',
        }, follow_redirects=True)
        assert b'already exists' in resp.data.lower()

    def test_delete_backend(self, client, admin_user, admin_with_totp, test_domain, test_domain_with_backend):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/domains/{test_domain}/backends/{test_domain_with_backend}/delete',
                           follow_redirects=True)
        assert b'removed' in resp.data.lower()

    def test_backend_config_page_loads(self, client, admin_user, admin_with_totp, test_domain, test_domain_with_backend):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.get(f'/admin/domains/{test_domain}/backends/{test_domain_with_backend}/config')
        assert resp.status_code == 200
        assert b'AWS Access Key ID' in resp.data

    def test_save_backend_credentials(self, client, admin_user, admin_with_totp, test_domain, test_domain_with_backend, app):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/domains/{test_domain}/backends/{test_domain_with_backend}/config', data={
            'aws_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'aws_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        }, follow_redirects=True)
        assert b'updated' in resp.data.lower()
        from models import BackendConfig
        with app.app_context():
            configs = BackendConfig.query.filter_by(domain_backend_id=test_domain_with_backend).all()
            assert len(configs) == 2

    def test_backend_config_does_not_leak_credentials(self, client, admin_user, admin_with_totp, test_domain, test_domain_with_backend, app):
        """Saved credentials must never appear in plaintext on the config page."""
        self._login_admin(client, admin_user, admin_with_totp)
        secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        client.post(f'/admin/domains/{test_domain}/backends/{test_domain_with_backend}/config', data={
            'aws_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'aws_secret_access_key': secret,
        }, follow_redirects=True)
        resp = client.get(f'/admin/domains/{test_domain}/backends/{test_domain_with_backend}/config')
        assert resp.status_code == 200
        assert secret.encode() not in resp.data
        assert b'type="password"' in resp.data


# ==============================================================================
# Hostname Management
# ==============================================================================

class TestHostnameManagement:

    def _login_admin(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)

    def test_admin_hostname_page_loads(self, client, admin_user, admin_with_totp, regular_user):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.get(f'/admin/users/{regular_user}/hostnames')
        assert resp.status_code == 200

    def test_admin_add_hostname(self, client, admin_user, admin_with_totp, regular_user, test_domain, app):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}/hostnames', data={
            'prefix': 'myhost',
            'domain_id': test_domain,
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'myhost.example.com' in resp.data
        from models import Hostname
        with app.app_context():
            hn = Hostname.query.filter_by(name='myhost.example.com').first()
            assert hn is not None
            assert hn.user_id == regular_user

    def test_admin_delete_hostname(self, client, admin_user, admin_with_totp, regular_user, test_hostname):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}/hostnames/{test_hostname}/delete', follow_redirects=True)
        assert b'removed' in resp.data.lower()

    def test_duplicate_hostname_rejected(self, client, admin_user, admin_with_totp, regular_user, test_domain, test_hostname):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}/hostnames', data={
            'prefix': 'test',
            'domain_id': test_domain,
        }, follow_redirects=True)
        assert b'already registered' in resp.data.lower()

    def test_user_self_service_hostnames(self, client, regular_user, regular_user_with_totp, test_domain):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get('/admin/hostnames')
        assert resp.status_code == 200

    def test_user_add_own_hostname(self, client, regular_user, regular_user_with_totp, test_domain, app):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.post('/admin/hostnames', data={
            'prefix': 'userhost',
            'domain_id': test_domain,
        }, follow_redirects=True)
        assert b'userhost.example.com' in resp.data
        from models import Hostname
        with app.app_context():
            hn = Hostname.query.filter_by(name='userhost.example.com').first()
            assert hn is not None
            assert hn.user_id == regular_user

    def test_user_delete_own_hostname(self, client, regular_user, regular_user_with_totp, test_hostname):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.post(f'/admin/hostnames/{test_hostname}/delete', follow_redirects=True)
        assert b'removed' in resp.data.lower()


# ==============================================================================
# Hostname Backend Selection
# ==============================================================================

class TestHostnameBackendSelection:

    def _login_admin(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)

    def test_hostname_backends_page_loads(self, client, admin_user, admin_with_totp, regular_user, test_hostname, test_domain_with_backend):
        """Admin can access hostname backends config page."""
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.get(f'/admin/users/{regular_user}/hostnames/{test_hostname}/backends')
        assert resp.status_code == 200
        assert b'Backend Configuration' in resp.data

    def test_select_specific_backend(self, client, admin_user, admin_with_totp, regular_user, test_hostname, test_domain_with_backend, app):
        """Admin can select specific backends for a hostname."""
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}/hostnames/{test_hostname}/backends', data={
            'backend_ids': test_domain_with_backend,
        }, follow_redirects=True)
        assert resp.status_code == 200
        from models import Hostname
        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            assert len(hn.backends) == 1
            assert hn.backends[0].id == test_domain_with_backend

    def test_clear_backend_selection(self, client, admin_user, admin_with_totp, regular_user, test_hostname, test_domain_with_backend, app):
        """Clearing backends reverts to using all domain backends."""
        self._login_admin(client, admin_user, admin_with_totp)
        # First select a backend
        client.post(f'/admin/users/{regular_user}/hostnames/{test_hostname}/backends', data={
            'backend_ids': test_domain_with_backend,
        }, follow_redirects=True)
        # Then clear selection
        resp = client.post(f'/admin/users/{regular_user}/hostnames/{test_hostname}/backends', data={
            # No backend_ids submitted means empty list
        }, follow_redirects=True)
        assert resp.status_code == 200
        from models import Hostname
        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            assert len(hn.backends) == 0  # Empty means use all domain backends

    def test_get_backends_returns_specific_when_set(self, app, test_hostname, test_domain_with_backend):
        """Hostname.get_backends() returns specific backends when configured."""
        from models import db, Hostname, DomainBackend
        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            backend = DomainBackend.query.get(test_domain_with_backend)
            hn.backends = [backend]
            db.session.commit()
            # get_backends() should return the specific backend
            result = hn.get_backends()
            assert len(result) == 1
            assert result[0].id == test_domain_with_backend

    def test_get_backends_returns_all_domain_when_not_set(self, app, test_hostname, test_domain_with_backend):
        """Hostname.get_backends() returns all domain backends when none specifically set."""
        from models import Hostname
        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            assert len(hn.backends) == 0  # No specific backends
            # get_backends() should return all domain backends
            result = hn.get_backends()
            assert len(result) == 1
            assert result[0].id == test_domain_with_backend

    def test_user_can_configure_own_hostname_backends(self, client, regular_user, regular_user_with_totp, test_hostname, test_domain_with_backend, app):
        """User can configure backends for their own hostname."""
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get(f'/admin/hostnames/{test_hostname}/backends')
        assert resp.status_code == 200
        resp = client.post(f'/admin/hostnames/{test_hostname}/backends', data={
            'backend_ids': test_domain_with_backend,
        }, follow_redirects=True)
        assert resp.status_code == 200
        from models import Hostname
        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            assert len(hn.backends) == 1

    def test_user_cannot_configure_others_hostname(self, client, admin_user, admin_with_totp, regular_user, regular_user_with_totp, test_hostname, app):
        """User cannot access another user's hostname backends."""
        # Create a hostname for admin
        from models import db, Hostname, Domain
        with app.app_context():
            domain = Domain.query.first()
            admin_hn = Hostname(name='admin.example.com', domain_id=domain.id, user_id=admin_user)
            db.session.add(admin_hn)
            db.session.commit()
            admin_hn_id = admin_hn.id

        # Login as regular user and try to access admin's hostname
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get(f'/admin/hostnames/{admin_hn_id}/backends', follow_redirects=True)
        assert b'Access denied' in resp.data


# ==============================================================================
# Miscellaneous Routes
# ==============================================================================

class TestMiscRoutes:

    def test_root_redirects(self, client):
        resp = client.get('/', follow_redirects=False)
        assert resp.status_code == 302

    def test_help_requires_auth(self, client):
        resp = client.get('/admin/help', follow_redirects=False)
        assert resp.status_code == 302
        assert 'login' in resp.headers['Location']

    def test_static_css_loads(self, client):
        resp = client.get('/static/style.css')
        assert resp.status_code == 200

    def test_help_page_loads_when_authenticated(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.get('/admin/help')
        assert resp.status_code == 200


# ==============================================================================
# Boot-time Admin Creation
# ==============================================================================

class TestBootAdminCreation:

    def test_fails_without_admin_password(self, tmp_path, monkeypatch):
        """App refuses to start when no admin exists and ADMIN_PASSWORD is not set."""
        from tests.conftest import TestConfig
        monkeypatch.delenv('ADMIN_PASSWORD', raising=False)
        config = TestConfig(tmp_path)
        config.TESTING = False  # enable boot-time admin check
        from dyndns import create_app
        with pytest.raises(RuntimeError, match='ADMIN_PASSWORD is not set'):
            create_app(config_class=config)

    def test_creates_admin_from_bcrypt_hash(self, tmp_path, monkeypatch):
        """App creates admin user on boot when ADMIN_PASSWORD is a bcrypt hash."""
        from tests.conftest import TestConfig
        password_hash = _hash_password('bootpass')
        monkeypatch.setenv('ADMIN_PASSWORD', password_hash)
        config = TestConfig(tmp_path)
        config.TESTING = False
        from dyndns import create_app
        application = create_app(config_class=config)
        from models import User
        with application.app_context():
            admin = User.query.filter_by(role='admin').first()
            assert admin is not None
            assert admin.username == 'admin'
            assert bcrypt.checkpw(b'bootpass', admin.password_hash.encode())

    def test_creates_admin_from_plaintext(self, tmp_path, monkeypatch):
        """App creates admin user on boot when ADMIN_PASSWORD is plaintext."""
        from tests.conftest import TestConfig
        monkeypatch.setenv('ADMIN_PASSWORD', 'my-plain-password')
        config = TestConfig(tmp_path)
        config.TESTING = False
        from dyndns import create_app
        application = create_app(config_class=config)
        from models import User
        with application.app_context():
            admin = User.query.filter_by(role='admin').first()
            assert admin is not None
            assert admin.username == 'admin'
            # Password was hashed at boot — verify plaintext works
            assert bcrypt.checkpw(b'my-plain-password', admin.password_hash.encode())
            # Stored hash should be bcrypt, not plaintext
            assert admin.password_hash.startswith('$2b$')

    def test_skips_if_admin_exists(self, tmp_path, monkeypatch):
        """App does not create a second admin if one already exists."""
        from tests.conftest import TestConfig
        password_hash = _hash_password('firstpass')
        monkeypatch.setenv('ADMIN_PASSWORD', password_hash)
        config = TestConfig(tmp_path)
        config.TESTING = False
        from dyndns import create_app
        from models import User
        # First boot — creates admin
        create_app(config_class=config)
        # Second boot — no ADMIN_PASSWORD needed, admin already exists
        monkeypatch.delenv('ADMIN_PASSWORD', raising=False)
        app2 = create_app(config_class=config)
        with app2.app_context():
            admins = User.query.filter_by(role='admin').all()
            assert len(admins) == 1


# ==============================================================================
# CheckIP Endpoint
# ==============================================================================

class TestCheckIP:

    def test_checkip_returns_html(self, client):
        resp = client.get('/nic/checkip')
        assert resp.status_code == 200
        assert resp.mimetype == 'text/html'
        assert b'Current IP Address:' in resp.data

    def test_checkip_plain_format(self, client):
        resp = client.get('/nic/checkip?format=plain')
        assert resp.status_code == 200
        assert resp.mimetype == 'text/plain'
        # Should be just the IP, no HTML
        assert b'<html>' not in resp.data

    def test_checkip_no_auth_required(self, client):
        """checkip endpoint works without credentials."""
        resp = client.get('/nic/checkip')
        assert resp.status_code == 200


# ==============================================================================
# TTL Management
# ==============================================================================

class TestTTLManagement:

    def test_hostname_default_ttl(self, app, regular_user, test_domain):
        from models import db, Hostname
        with app.app_context():
            hn = Hostname(name='ttltest.example.com', domain_id=test_domain, user_id=regular_user)
            db.session.add(hn)
            db.session.commit()
            assert hn.ttl == 60

    def test_hostname_custom_ttl(self, app, regular_user, test_domain):
        from models import db, Hostname
        with app.app_context():
            hn = Hostname(name='ttltest2.example.com', domain_id=test_domain, user_id=regular_user, ttl=300)
            db.session.add(hn)
            db.session.commit()
            assert hn.ttl == 300

    def test_admin_create_hostname_with_ttl(self, client, admin_user, admin_with_totp, regular_user, test_domain, app):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}/hostnames', data={
            'prefix': 'ttlhost',
            'domain_id': test_domain,
            'ttl': 120,
        }, follow_redirects=True)
        assert resp.status_code == 200
        from models import Hostname
        with app.app_context():
            hn = Hostname.query.filter_by(name='ttlhost.example.com').first()
            assert hn is not None
            assert hn.ttl == 120

    def test_user_create_hostname_with_ttl(self, client, regular_user, regular_user_with_totp, test_domain, app):
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.post('/admin/hostnames', data={
            'prefix': 'myttlhost',
            'domain_id': test_domain,
            'ttl': 300,
        }, follow_redirects=True)
        assert resp.status_code == 200
        from models import Hostname
        with app.app_context():
            hn = Hostname.query.filter_by(name='myttlhost.example.com').first()
            assert hn is not None
            assert hn.ttl == 300

    def test_ttl_validation_too_low(self, client, admin_user, admin_with_totp, regular_user, test_domain):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}/hostnames', data={
            'prefix': 'lowttl',
            'domain_id': test_domain,
            'ttl': 5,
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'TTL must be between' in resp.data

    def test_ttl_validation_too_high(self, client, admin_user, admin_with_totp, regular_user, test_domain):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}/hostnames', data={
            'prefix': 'highttl',
            'domain_id': test_domain,
            'ttl': 100000,
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'TTL must be between' in resp.data

    def test_update_ttl_via_backends_page(self, client, admin_user, admin_with_totp, regular_user,
                                           test_domain, test_hostname, app):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}/hostnames/{test_hostname}/backends', data={
            'ttl': 600,
            'save_ttl': '1',
        }, follow_redirects=True)
        assert resp.status_code == 200
        from models import Hostname
        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            assert hn.ttl == 600

    def test_ttl_passed_to_backend(self, client, regular_user, test_domain, test_hostname, app):
        """TTL from hostname is passed to createrecords()."""
        from models import db, Hostname, DomainBackend, BackendConfig, encrypt_value
        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            hn.ttl = 300
            # Set up a backend with credentials
            backend = DomainBackend(domain_id=test_domain, backend_type='aws')
            db.session.add(backend)
            db.session.commit()
            for key, val in [('aws_access_key_id', 'test'), ('aws_secret_access_key', 'test')]:
                cfg = BackendConfig(domain_backend_id=backend.id, config_key=key,
                                    config_value=encrypt_value(val))
                db.session.add(cfg)
            hn.backends = [backend]
            db.session.commit()

        with patch('dyndns.Accounts') as mock_accounts:
            mock_account = MagicMock()
            mock_account.hostnameperzone.return_value = {'example.com': ['test.example.com']}
            mock_account.createrecords.return_value = {'test.example.com': 'good'}
            mock_accounts.get.return_value = mock_account
            auth = base64.b64encode(b'testuser:testpass123').decode()
            client.get('/nic/update?hostname=test.example.com&myip=192.0.2.1',
                        headers={'Authorization': f'Basic {auth}'})
            if mock_account.createrecords.called:
                _, kwargs = mock_account.createrecords.call_args
                assert kwargs.get('ttl') == 300


# ==============================================================================
# Rate Limiting
# ==============================================================================

class TestRateLimiting:

    def test_rate_limiter_allows_requests(self, app):
        from rate_limiter import RateLimiter
        rl = RateLimiter()
        with app.app_context():
            assert not rl.is_rate_limited(1, per_minute=10, per_hour=100)

    def test_rate_limiter_blocks_after_limit(self, app):
        from rate_limiter import RateLimiter
        rl = RateLimiter()
        with app.app_context():
            for _ in range(5):
                rl.record_request(1)
            assert rl.is_rate_limited(1, per_minute=5, per_hour=100)

    def test_rate_limiter_per_hour_limit(self, app):
        from rate_limiter import RateLimiter
        rl = RateLimiter()
        with app.app_context():
            for _ in range(10):
                rl.record_request(1)
            assert rl.is_rate_limited(1, per_minute=100, per_hour=10)

    def test_rate_limiter_independent_users(self, app):
        from rate_limiter import RateLimiter
        rl = RateLimiter()
        with app.app_context():
            for _ in range(5):
                rl.record_request(1)
            # User 2 should not be affected
            assert not rl.is_rate_limited(2, per_minute=5, per_hour=100)

    def test_abuse_returned_on_rate_limit(self, client, regular_user, test_domain, test_hostname, app):
        """Rate limited requests return 'abuse'."""
        from models import db, RateLimitConfig
        with app.app_context():
            # Set a very low rate limit for testing
            user_rl = RateLimitConfig(user_id=regular_user, is_global=False,
                                       requests_per_minute=1, requests_per_hour=1)
            db.session.add(user_rl)
            db.session.commit()

        auth = base64.b64encode(b'testuser:testpass123').decode()
        headers = {'Authorization': f'Basic {auth}'}
        # First request should go through (or be blocked by missing backend, not rate limit)
        client.get('/nic/update?hostname=test.example.com&myip=192.0.2.1', headers=headers)
        # Second request should be rate limited
        resp = client.get('/nic/update?hostname=test.example.com&myip=192.0.2.1', headers=headers)
        assert b'abuse' in resp.data

    def test_admin_rate_limit_page(self, client, admin_user, admin_with_totp, app):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.get('/admin/rate-limits')
        assert resp.status_code == 200
        assert b'Global Defaults' in resp.data

    def test_admin_update_global_rate_limit(self, client, admin_user, admin_with_totp, app):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post('/admin/rate-limits', data={
            'requests_per_minute': 50,
            'requests_per_hour': 1000,
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'Global rate limits updated' in resp.data
        from models import RateLimitConfig
        with app.app_context():
            config = RateLimitConfig.query.filter_by(is_global=True).first()
            assert config.requests_per_minute == 50
            assert config.requests_per_hour == 1000

    def test_admin_create_user_rate_limit_override(self, client, admin_user, admin_with_totp, regular_user, app):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post(f'/admin/rate-limits/user/{regular_user}', data={
            'requests_per_minute': 10,
            'requests_per_hour': 100,
        }, follow_redirects=True)
        assert resp.status_code == 200
        from models import RateLimitConfig
        with app.app_context():
            config = RateLimitConfig.query.filter_by(user_id=regular_user).first()
            assert config is not None
            assert config.requests_per_minute == 10

    def test_admin_delete_user_rate_limit_override(self, client, admin_user, admin_with_totp, regular_user, app):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        # Create override first
        client.post(f'/admin/rate-limits/user/{regular_user}', data={
            'requests_per_minute': 10,
            'requests_per_hour': 100,
        }, follow_redirects=True)
        # Delete it
        resp = client.post(f'/admin/rate-limits/user/{regular_user}/delete', follow_redirects=True)
        assert resp.status_code == 200
        from models import RateLimitConfig
        with app.app_context():
            config = RateLimitConfig.query.filter_by(user_id=regular_user).first()
            assert config is None


# ==============================================================================
# Health Checks
# ==============================================================================

class TestHealthChecks:

    def test_global_rate_limit_created_on_boot(self, app):
        from models import RateLimitConfig
        with app.app_context():
            config = RateLimitConfig.query.filter_by(is_global=True).first()
            assert config is not None
            assert config.requests_per_minute == 30

    def test_health_check_config_created_on_boot(self, app):
        from models import HealthCheckConfig
        with app.app_context():
            config = HealthCheckConfig.query.first()
            assert config is not None
            assert config.enabled is False

    def test_last_ip_tracked_on_update(self, client, regular_user, test_domain, test_hostname, app):
        """Successful update stores last_ip_v4 on the hostname."""
        from models import db, Hostname, DomainBackend, BackendConfig, encrypt_value
        with app.app_context():
            backend = DomainBackend(domain_id=test_domain, backend_type='aws')
            db.session.add(backend)
            db.session.commit()
            for key, val in [('aws_access_key_id', 'test'), ('aws_secret_access_key', 'test')]:
                cfg = BackendConfig(domain_backend_id=backend.id, config_key=key,
                                    config_value=encrypt_value(val))
                db.session.add(cfg)
            hn = Hostname.query.get(test_hostname)
            hn.backends = [backend]
            db.session.commit()

        with patch('dyndns.Accounts') as mock_accounts:
            mock_account = MagicMock()
            mock_account.hostnameperzone.return_value = {'example.com': ['test.example.com']}
            mock_account.createrecords.return_value = {'test.example.com': 'good'}
            mock_accounts.get.return_value = mock_account
            auth = base64.b64encode(b'testuser:testpass123').decode()
            resp = client.get('/nic/update?hostname=test.example.com&myip=192.0.2.1',
                              headers={'Authorization': f'Basic {auth}'})
            assert b'good' in resp.data

        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            assert hn.last_ip_v4 == '192.0.2.1'
            assert hn.last_updated_at is not None

    def test_health_check_list_page(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.get('/admin/health-checks')
        assert resp.status_code == 200
        assert b'Health Checks' in resp.data

    def test_health_check_config_page(self, client, admin_user, admin_with_totp):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.get('/admin/health-checks/config')
        assert resp.status_code == 200
        assert b'Health Check Configuration' in resp.data

    def test_health_check_update_config(self, client, admin_user, admin_with_totp, app):
        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post('/admin/health-checks/config', data={
            'enabled': 'y',
            'check_interval_minutes': 30,
        }, follow_redirects=True)
        assert resp.status_code == 200
        from models import HealthCheckConfig
        with app.app_context():
            config = HealthCheckConfig.query.first()
            assert config.enabled is True
            assert config.check_interval_minutes == 30

    def test_run_health_checks_manually(self, client, admin_user, admin_with_totp, regular_user,
                                         test_domain, test_hostname, app):
        """Run health checks via the admin UI."""
        from models import db, Hostname, HealthCheckConfig
        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            hn.last_ip_v4 = '192.0.2.1'
            config = HealthCheckConfig.query.first()
            config.enabled = True
            db.session.commit()

        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        with patch('health_checker.dns.resolver.resolve') as mock_resolve:
            mock_answer = MagicMock()
            mock_answer.__iter__ = lambda self: iter([MagicMock(address='192.0.2.1')])
            mock_answer.__getitem__ = lambda self, idx: MagicMock(address='192.0.2.1')
            mock_resolve.return_value = mock_answer
            resp = client.post('/admin/health-checks/run', follow_redirects=True)
            assert resp.status_code == 200
            assert b'Health check completed' in resp.data

        from models import HealthCheck
        with app.app_context():
            checks = HealthCheck.query.all()
            assert len(checks) >= 1
            assert checks[0].status == 'ok'

    def test_health_check_detects_mismatch(self, app, regular_user, test_domain, test_hostname):
        """Health check detects when DNS doesn't match expected IP."""
        from models import db, Hostname, HealthCheck, HealthCheckConfig
        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            hn.last_ip_v4 = '192.0.2.1'
            config = HealthCheckConfig.query.first()
            config.enabled = True
            db.session.commit()

        with patch('health_checker.dns.resolver.resolve') as mock_resolve:
            mock_answer = MagicMock()
            mock_answer.__iter__ = lambda self: iter([MagicMock(address='192.0.2.99')])
            mock_answer.__getitem__ = lambda self, idx: MagicMock(address='192.0.2.99')
            mock_resolve.return_value = mock_answer

            from health_checker import run_health_checks
            run_health_checks(app)

        with app.app_context():
            checks = HealthCheck.query.all()
            assert len(checks) >= 1
            assert checks[0].status == 'mismatch'
            assert checks[0].expected_ip == '192.0.2.1'
            assert checks[0].actual_ip == '192.0.2.99'

    def test_health_check_detects_missing(self, app, regular_user, test_domain, test_hostname):
        """Health check detects when DNS record is missing."""
        from models import db, Hostname, HealthCheck, HealthCheckConfig
        import dns.resolver
        with app.app_context():
            hn = Hostname.query.get(test_hostname)
            hn.last_ip_v4 = '192.0.2.1'
            config = HealthCheckConfig.query.first()
            config.enabled = True
            db.session.commit()

        with patch('health_checker.dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN):
            from health_checker import run_health_checks
            run_health_checks(app)

        with app.app_context():
            checks = HealthCheck.query.all()
            assert len(checks) >= 1
            assert checks[0].status == 'missing'

    def test_health_check_clear(self, client, admin_user, admin_with_totp, app):
        """Admin can clear health check results."""
        from models import db, HealthCheck
        with app.app_context():
            hc = HealthCheck(hostname='test.example.com', expected_ip='192.0.2.1',
                             actual_ip='192.0.2.1', record_type='A', status='ok')
            db.session.add(hc)
            db.session.commit()

        login_user_full(client, 'admin', ADMIN_PASSWORD, totp_secret=admin_with_totp)
        resp = client.post('/admin/health-checks/clear', follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            assert HealthCheck.query.count() == 0

    def test_health_check_requires_admin(self, client, regular_user, regular_user_with_totp):
        """Non-admin users cannot access health check pages."""
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get('/admin/health-checks', follow_redirects=True)
        assert b'Admin access required' in resp.data

    def test_rate_limit_requires_admin(self, client, regular_user, regular_user_with_totp):
        """Non-admin users cannot access rate limit pages."""
        login_user_full(client, 'testuser', TEST_PASSWORD, totp_secret=regular_user_with_totp)
        resp = client.get('/admin/rate-limits', follow_redirects=True)
        assert b'Admin access required' in resp.data
