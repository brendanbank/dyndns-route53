import base64
import bcrypt
import pytest
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

    def test_create_user(self, client, admin_user, admin_with_totp):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post('/admin/users/new', data={
            'username': 'newuser',
            'password': 'newpass12345',
            'role': 'user',
            'is_active': 'y',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'created' in resp.data.lower() or b'newuser' in resp.data

    def test_edit_user(self, client, admin_user, admin_with_totp, regular_user, app):
        self._login_admin(client, admin_user, admin_with_totp)
        resp = client.post(f'/admin/users/{regular_user}', data={
            'username': 'testuser_renamed',
            'password': '',
            'role': 'user',
            'is_active': 'y',
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
