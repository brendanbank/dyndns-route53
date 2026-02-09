import re
import bcrypt
import pyotp
import pytest
from cryptography.fernet import Fernet


class TestConfig:
    TESTING = True
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-secret-key'
    FERNET_KEY = Fernet.generate_key().decode()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {'connect_args': {'timeout': 30}}

    def __init__(self, tmp_path):
        db_path = str(tmp_path / 'dyndns.db')
        events_path = str(tmp_path / 'events.db')
        self.SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
        self.SQLALCHEMY_BINDS = {'events': f'sqlite:///{events_path}'}


# --- ENV cleanup ---

ENV_VARS_TO_CLEAR = [
    'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
    'NSUPDATE_KEY', 'NSUPDATE_ALGO', 'NSUPDATE_SECRET', 'NSUPDATE_NAMESERVER',
    'DOMAINS', 'USERNAME', 'PASSWORD',
]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ENV_VARS_TO_CLEAR:
        monkeypatch.delenv(var, raising=False)


# --- App / client fixtures ---

@pytest.fixture
def app(tmp_path):
    config = TestConfig(tmp_path)
    from dyndns import create_app
    application = create_app(config_class=config)
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


# --- User fixtures ---

TEST_PASSWORD = 'testpass123'
ADMIN_PASSWORD = 'adminpass123'


def _hash_password(plaintext):
    return bcrypt.hashpw(plaintext.encode('utf8'), bcrypt.gensalt()).decode()


@pytest.fixture
def admin_user(app):
    from models import db, User
    with app.app_context():
        user = User(
            username='admin',
            password_hash=_hash_password(ADMIN_PASSWORD),
            role='admin',
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        uid = user.id
    return uid


@pytest.fixture
def regular_user(app):
    from models import db, User
    with app.app_context():
        user = User(
            username='testuser',
            password_hash=_hash_password(TEST_PASSWORD),
            role='user',
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        uid = user.id
    return uid


@pytest.fixture
def admin_with_totp(app, admin_user):
    from models import db, User
    secret = pyotp.random_base32()
    with app.app_context():
        user = User.query.get(admin_user)
        user.set_totp_secret(secret)
        db.session.commit()
    return secret


@pytest.fixture
def regular_user_with_totp(app, regular_user):
    from models import db, User
    secret = pyotp.random_base32()
    with app.app_context():
        user = User.query.get(regular_user)
        user.set_totp_secret(secret)
        db.session.commit()
    return secret


@pytest.fixture
def inactive_user(app):
    from models import db, User
    with app.app_context():
        user = User(
            username='inactive',
            password_hash=_hash_password(TEST_PASSWORD),
            role='user',
            is_active=False,
        )
        db.session.add(user)
        db.session.commit()
        uid = user.id
    return uid


# --- Domain / Hostname fixtures ---

@pytest.fixture
def test_domain(app):
    from models import db, Domain
    with app.app_context():
        domain = Domain(name='example.com')
        db.session.add(domain)
        db.session.commit()
        did = domain.id
    return did


@pytest.fixture
def test_domain_with_backend(app, test_domain):
    from models import db, DomainBackend
    with app.app_context():
        db_backend = DomainBackend(domain_id=test_domain, backend_type='aws')
        db.session.add(db_backend)
        db.session.commit()
        bid = db_backend.id
    return bid


@pytest.fixture
def test_hostname(app, regular_user, test_domain):
    from models import db, Hostname
    with app.app_context():
        hn = Hostname(name='test.example.com', domain_id=test_domain, user_id=regular_user)
        db.session.add(hn)
        db.session.commit()
        hid = hn.id
    return hid


# --- Helpers ---

def get_csrf_token(html):
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    if match:
        return match.group(1)
    return None


def login_user_full(client, username, password, totp_secret=None):
    """Complete login flow: password -> TOTP setup or verify -> logged in.
    Returns the final response."""
    # Step 1: POST login
    resp = client.post('/admin/login', data={
        'username': username,
        'password': password,
    }, follow_redirects=False)

    if resp.status_code not in (302, 303):
        return resp

    location = resp.headers.get('Location', '')

    # Step 2: TOTP
    if 'totp-verify' in location:
        assert totp_secret is not None, 'User has TOTP but no secret provided'
        code = pyotp.TOTP(totp_secret).now()
        resp = client.post('/admin/totp-verify', data={'code': code}, follow_redirects=True)
    elif 'totp-setup' in location:
        # Get the pending secret from session — extract from the setup page
        resp = client.get('/admin/totp-setup')
        html = resp.data.decode()
        # Extract secret from the manual-entry input field
        secret_match = re.search(r'value="([A-Z2-7]{32})"', html)
        if not secret_match:
            secret_match = re.search(r'([A-Z2-7]{32})', html)
        assert secret_match, 'Could not find TOTP secret on setup page'
        setup_secret = secret_match.group(1)
        code = pyotp.TOTP(setup_secret).now()
        resp = client.post('/admin/totp-setup', data={'code': code}, follow_redirects=True)
    else:
        resp = client.get(location, follow_redirects=True)

    return resp
