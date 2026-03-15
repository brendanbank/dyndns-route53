import io
import bcrypt
import pyotp
import qrcode
import qrcode.image.svg
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, Domain, DomainBackend, BackendConfig, Hostname, Event, encrypt_value
from forms import LoginForm, UserForm, PasswordChangeForm, TOTPVerifyForm, TOTPSetupForm, DomainForm, HostnameForm
from auth import admin_required, authenticate_dyndns_user

web_bp = Blueprint('web', __name__)

ITEMS_PER_PAGE = 20

AWS_CONFIG_KEYS = [
    ('aws_access_key_id', 'AWS Access Key ID'),
    ('aws_secret_access_key', 'AWS Secret Access Key'),
]

NSUPDATE_CONFIG_KEYS = [
    ('nsupdate_key', 'TSIG Key Name'),
    ('nsupdate_algo', 'TSIG Algorithm'),
    ('nsupdate_secret', 'TSIG Secret'),
    ('nsupdate_nameserver', 'Nameserver'),
]

HETZNER_CONFIG_KEYS = [
    ('hetzner_api_token', 'Hetzner DNS API Token'),
]

BACKEND_CONFIG_KEYS = {
    'aws': AWS_CONFIG_KEYS,
    'nsupdate': NSUPDATE_CONFIG_KEYS,
    'hetzner': HETZNER_CONFIG_KEYS,
}


@web_bp.route('/')
def index():
    return redirect(url_for('web.dashboard'))


# --- Authentication ---

@web_bp.route('/admin/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('web.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = authenticate_dyndns_user(form.username.data, form.password.data)
        if user:
            if not user.web_login:
                flash('Web login is not enabled for this account.', 'danger')
                return render_template('login.html', form=form)
            session['pending_2fa_user_id'] = user.id
            session['next_url'] = request.args.get('next')
            if user.has_totp:
                return redirect(url_for('web.totp_verify'))
            else:
                return redirect(url_for('web.totp_setup'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)


@web_bp.route('/admin/logout')
@login_required
def logout():
    logout_user()
    session.pop('pending_2fa_user_id', None)
    session.pop('pending_totp_secret', None)
    session.pop('next_url', None)
    flash('Logged out.', 'info')
    return redirect(url_for('web.login'))


def _get_pending_2fa_user():
    user_id = session.get('pending_2fa_user_id')
    if not user_id:
        return None
    user = User.query.get(user_id)
    if not user or not user.is_active:
        session.pop('pending_2fa_user_id', None)
        return None
    return user


@web_bp.route('/admin/totp-verify', methods=['GET', 'POST'])
def totp_verify():
    user = _get_pending_2fa_user()
    if not user:
        return redirect(url_for('web.login'))
    if not user.has_totp:
        return redirect(url_for('web.totp_setup'))

    form = TOTPVerifyForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.get_totp_secret())
        if totp.verify(form.code.data, valid_window=1):
            next_url = session.pop('next_url', None)
            session.pop('pending_2fa_user_id', None)
            session.pop('pending_totp_secret', None)
            login_user(user)
            return redirect(next_url or url_for('web.dashboard'))
        flash('Invalid authentication code.', 'danger')
    return render_template('totp_verify.html', form=form)


@web_bp.route('/admin/totp-setup', methods=['GET', 'POST'])
def totp_setup():
    user = _get_pending_2fa_user()
    if not user:
        return redirect(url_for('web.login'))
    if user.has_totp:
        return redirect(url_for('web.totp_verify'))

    # Generate or retrieve pending secret
    if 'pending_totp_secret' not in session:
        session['pending_totp_secret'] = pyotp.random_base32()
    secret = session['pending_totp_secret']

    form = TOTPSetupForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(secret)
        if totp.verify(form.code.data, valid_window=1):
            user.set_totp_secret(secret)
            db.session.commit()
            next_url = session.pop('next_url', None)
            session.pop('pending_2fa_user_id', None)
            session.pop('pending_totp_secret', None)
            login_user(user)
            flash('Two-factor authentication enabled.', 'success')
            return redirect(next_url or url_for('web.dashboard'))
        flash('Invalid verification code. Please try again.', 'danger')

    # Generate QR code as SVG
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name='DynDNS')
    img = qrcode.make(provisioning_uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    qr_svg = buf.getvalue().decode()

    return render_template('totp_setup.html', form=form, qr_svg=qr_svg, secret=secret)


# --- Dashboard ---

@web_bp.route('/admin/')
@login_required
def dashboard():
    if current_user.is_admin:
        user_count = User.query.count()
        domain_count = Domain.query.count()
        hostname_count = Hostname.query.count()
        event_count = Event.query.count()
        recent_events = Event.query.order_by(Event.created_at.desc()).limit(10).all()
    else:
        user_hostnames = Hostname.query.filter_by(user_id=current_user.id).all()
        recent_events = Event.query.filter_by(user_id=current_user.id).order_by(Event.created_at.desc()).limit(10).all()

    # Build lookup dicts for linking users and hostnames in recent events
    user_ids = {e.user_id for e in recent_events}
    user_map = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}
    hostname_names = {e.hostname for e in recent_events if e.hostname}
    hostname_map = {h.name: h for h in Hostname.query.filter(Hostname.name.in_(hostname_names)).all()} if hostname_names else {}

    if current_user.is_admin:
        return render_template('dashboard.html', user_count=user_count, domain_count=domain_count,
                               hostname_count=hostname_count, event_count=event_count,
                               recent_events=recent_events, user_map=user_map, hostname_map=hostname_map)
    else:
        return render_template('dashboard.html', user_hostnames=user_hostnames, recent_events=recent_events,
                               user_map=user_map, hostname_map=hostname_map)


# --- User Management (Admin) ---

@web_bp.route('/admin/users')
@login_required
@admin_required
def user_list():
    users = User.query.order_by(User.username).all()
    return render_template('users/list.html', users=users)


@web_bp.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def user_create():
    form = UserForm()
    if form.validate_on_submit():
        hashed = bcrypt.hashpw(form.password.data.encode('utf8'), bcrypt.gensalt()).decode()
        user = User(username=form.username.data, password_hash=hashed,
                    role=form.role.data, is_active=form.is_active.data,
                    web_login=form.web_login.data)
        db.session.add(user)
        db.session.commit()
        flash(f'User "{user.username}" created.', 'success')
        return redirect(url_for('web.user_edit', user_id=user.id))
    return render_template('users/edit.html', form=form, is_new=True)


@web_bp.route('/admin/users/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def user_edit(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm(original_username=user.username, obj=user)
    if form.validate_on_submit():
        user.username = form.username.data
        if form.password.data:
            user.password_hash = bcrypt.hashpw(form.password.data.encode('utf8'), bcrypt.gensalt()).decode()
        user.role = form.role.data
        user.is_active = form.is_active.data
        user.web_login = form.web_login.data
        db.session.commit()
        flash(f'User "{user.username}" updated.', 'success')
        return redirect(url_for('web.user_edit', user_id=user.id))
    return render_template('users/edit.html', form=form, user=user, is_new=False)


@web_bp.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('web.user_list'))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{username}" deleted.', 'success')
    return redirect(url_for('web.user_list'))


# --- Domain Management (Admin) ---

@web_bp.route('/admin/domains', methods=['GET', 'POST'])
@login_required
@admin_required
def domain_list():
    form = DomainForm()
    if form.validate_on_submit():
        name = form.name.data.strip().lower()
        existing = Domain.query.filter_by(name=name).first()
        if existing:
            flash(f'Domain "{name}" already exists.', 'warning')
        else:
            domain = Domain(name=name)
            db.session.add(domain)
            db.session.commit()
            flash(f'Domain "{name}" created.', 'success')
        return redirect(url_for('web.domain_list'))
    domains = Domain.query.order_by(Domain.name).all()
    return render_template('domains/list.html', domains=domains, form=form)


@web_bp.route('/admin/domains/<int:domain_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def domain_edit(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    form = DomainForm(obj=domain)
    if form.validate_on_submit():
        new_name = form.name.data.strip().lower()
        if new_name != domain.name:
            existing = Domain.query.filter_by(name=new_name).first()
            if existing:
                flash(f'Domain "{new_name}" already exists.', 'warning')
                return redirect(url_for('web.domain_edit', domain_id=domain.id))
        domain.name = new_name
        db.session.commit()
        flash(f'Domain "{domain.name}" updated.', 'success')
        return redirect(url_for('web.domain_edit', domain_id=domain.id))
    return render_template('domains/edit.html', domain=domain, form=form)


@web_bp.route('/admin/domains/<int:domain_id>/delete', methods=['POST'])
@login_required
@admin_required
def domain_delete(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    name = domain.name
    db.session.delete(domain)
    db.session.commit()
    flash(f'Domain "{name}" deleted.', 'success')
    return redirect(url_for('web.domain_list'))


# --- Domain Backend Management (Admin) ---

@web_bp.route('/admin/domains/<int:domain_id>/backends/new', methods=['GET', 'POST'])
@login_required
@admin_required
def domain_backend_add(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    if request.method == 'POST':
        backend_type = request.form.get('backend_type', '').strip()
        if backend_type not in BACKEND_CONFIG_KEYS:
            flash('Invalid backend type.', 'danger')
        else:
            existing = DomainBackend.query.filter_by(domain_id=domain.id, backend_type=backend_type).first()
            if existing:
                flash(f'Backend "{backend_type}" already exists for this domain.', 'warning')
            else:
                db_backend = DomainBackend(domain_id=domain.id, backend_type=backend_type)
                db.session.add(db_backend)
                db.session.commit()
                flash(f'Backend "{backend_type}" added.', 'success')
                return redirect(url_for('web.domain_backend_config', domain_id=domain.id, db_id=db_backend.id))
        return redirect(url_for('web.domain_edit', domain_id=domain.id))
    return render_template('domains/backend_add.html', domain=domain, backend_types=BACKEND_CONFIG_KEYS.keys())


@web_bp.route('/admin/domains/<int:domain_id>/backends/<int:db_id>/config', methods=['GET', 'POST'])
@login_required
@admin_required
def domain_backend_config(domain_id, db_id):
    domain = Domain.query.get_or_404(domain_id)
    db_backend = DomainBackend.query.get_or_404(db_id)

    config_keys = BACKEND_CONFIG_KEYS.get(db_backend.backend_type)
    if not config_keys:
        flash('Invalid backend type.', 'danger')
        return redirect(url_for('web.domain_edit', domain_id=domain.id))

    existing = {c.config_key: c for c in db_backend.configs}

    if request.method == 'POST':
        for key, label in config_keys:
            value = request.form.get(key, '').strip()
            clear = request.form.get(f'{key}_clear')
            if clear and key in existing:
                db.session.delete(existing[key])
            elif value:
                if key in existing:
                    existing[key].config_value = encrypt_value(value)
                else:
                    cfg = BackendConfig(domain_backend_id=db_backend.id,
                                        config_key=key, config_value=encrypt_value(value))
                    db.session.add(cfg)
        db.session.commit()
        flash(f'Credentials for "{domain.name}" ({db_backend.backend_type}) updated.', 'success')
        return redirect(url_for('web.domain_backend_config', domain_id=domain.id, db_id=db_backend.id))

    has_value = {key for key, label in config_keys if key in existing}

    return render_template('domains/backend_config.html', domain=domain, db_backend=db_backend,
                           config_keys=config_keys, has_value=has_value)


@web_bp.route('/admin/domains/<int:domain_id>/backends/<int:db_id>/delete', methods=['POST'])
@login_required
@admin_required
def domain_backend_delete(domain_id, db_id):
    db_backend = DomainBackend.query.get_or_404(db_id)
    db.session.delete(db_backend)
    db.session.commit()
    flash('Backend removed.', 'success')
    return redirect(url_for('web.domain_edit', domain_id=domain_id))


# --- Hostname Management (Admin) ---

@web_bp.route('/admin/users/<int:user_id>/hostnames', methods=['GET', 'POST'])
@login_required
@admin_required
def user_hostnames(user_id):
    user = User.query.get_or_404(user_id)
    form = HostnameForm()
    form.domain_id.choices = [(d.id, d.name) for d in Domain.query.order_by(Domain.name).all()]

    if form.validate_on_submit():
        domain = Domain.query.get(form.domain_id.data)
        if not domain:
            flash('Invalid domain.', 'danger')
        else:
            fqdn = f'{form.prefix.data.strip().lower()}.{domain.name}'
            existing = Hostname.query.filter_by(name=fqdn).first()
            if existing:
                flash(f'Hostname "{fqdn}" is already registered.', 'warning')
            else:
                hn = Hostname(name=fqdn, domain_id=domain.id, user_id=user.id)
                db.session.add(hn)
                db.session.commit()
                flash(f'Hostname "{fqdn}" added.', 'success')
            return redirect(url_for('web.user_hostnames', user_id=user.id))

    hostnames = Hostname.query.filter_by(user_id=user.id).order_by(Hostname.name).all()
    return render_template('hostnames/list.html', user=user, hostnames=hostnames, form=form, is_admin_view=True)


@web_bp.route('/admin/users/<int:user_id>/hostnames/<int:hn_id>/delete', methods=['POST'])
@login_required
@admin_required
def user_hostname_delete(user_id, hn_id):
    hn = Hostname.query.get_or_404(hn_id)
    db.session.delete(hn)
    db.session.commit()
    flash('Hostname removed.', 'success')
    return redirect(url_for('web.user_hostnames', user_id=user_id))


@web_bp.route('/admin/users/<int:user_id>/hostnames/<int:hn_id>/backends', methods=['GET', 'POST'])
@login_required
@admin_required
def user_hostname_backends(user_id, hn_id):
    """Admin: configure which backends a hostname uses."""
    user = User.query.get_or_404(user_id)
    hn = Hostname.query.get_or_404(hn_id)
    if hn.user_id != user.id:
        flash('Hostname does not belong to this user.', 'danger')
        return redirect(url_for('web.user_hostnames', user_id=user_id))

    domain_backends = hn.domain.backends

    if request.method == 'POST':
        selected_ids = request.form.getlist('backend_ids', type=int)
        # Clear and set new backends
        hn.backends = [b for b in domain_backends if b.id in selected_ids]
        db.session.commit()
        flash(f'Backend configuration for "{hn.name}" updated.', 'success')
        return redirect(url_for('web.user_hostnames', user_id=user_id))

    return render_template('hostnames/backends.html', user=user, hostname=hn,
                           domain_backends=domain_backends, is_admin_view=True)


# --- Hostname Management (User self-service) ---

@web_bp.route('/admin/hostnames', methods=['GET', 'POST'])
@login_required
def my_hostnames():
    form = HostnameForm()
    form.domain_id.choices = [(d.id, d.name) for d in Domain.query.order_by(Domain.name).all()]

    if form.validate_on_submit():
        domain = Domain.query.get(form.domain_id.data)
        if not domain:
            flash('Invalid domain.', 'danger')
        else:
            fqdn = f'{form.prefix.data.strip().lower()}.{domain.name}'
            existing = Hostname.query.filter_by(name=fqdn).first()
            if existing:
                flash(f'Hostname "{fqdn}" is already registered.', 'warning')
            else:
                hn = Hostname(name=fqdn, domain_id=domain.id, user_id=current_user.id)
                db.session.add(hn)
                db.session.commit()
                flash(f'Hostname "{fqdn}" added.', 'success')
            return redirect(url_for('web.my_hostnames'))

    hostnames = Hostname.query.filter_by(user_id=current_user.id).order_by(Hostname.name).all()
    return render_template('hostnames/list.html', user=current_user, hostnames=hostnames, form=form,
                           is_admin_view=False)


@web_bp.route('/admin/hostnames/<int:hn_id>/delete', methods=['POST'])
@login_required
def my_hostname_delete(hn_id):
    hn = Hostname.query.get_or_404(hn_id)
    if hn.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('web.my_hostnames'))
    db.session.delete(hn)
    db.session.commit()
    flash('Hostname removed.', 'success')
    return redirect(url_for('web.my_hostnames'))


@web_bp.route('/admin/hostnames/<int:hn_id>/backends', methods=['GET', 'POST'])
@login_required
def my_hostname_backends(hn_id):
    """User self-service: configure which backends a hostname uses."""
    hn = Hostname.query.get_or_404(hn_id)
    if hn.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied.', 'danger')
        return redirect(url_for('web.my_hostnames'))

    domain_backends = hn.domain.backends

    if request.method == 'POST':
        selected_ids = request.form.getlist('backend_ids', type=int)
        # Clear and set new backends
        hn.backends = [b for b in domain_backends if b.id in selected_ids]
        db.session.commit()
        flash(f'Backend configuration for "{hn.name}" updated.', 'success')
        return redirect(url_for('web.my_hostnames'))

    return render_template('hostnames/backends.html', user=current_user, hostname=hn,
                           domain_backends=domain_backends, is_admin_view=False)


# --- Events ---

@web_bp.route('/admin/events')
@login_required
def event_list():
    page = request.args.get('page', 1, type=int)
    username_filter = request.args.get('username', '')
    hostname_filter = request.args.get('hostname', '')

    query = Event.query

    if not current_user.is_admin:
        query = query.filter_by(user_id=current_user.id)

    if username_filter and current_user.is_admin:
        query = query.filter(Event.username == username_filter)
    if hostname_filter:
        query = query.filter(Event.hostname == hostname_filter)

    events = query.order_by(Event.created_at.desc()).paginate(page=page, per_page=ITEMS_PER_PAGE, error_out=False)

    # Build lookup dicts for linking users and hostnames
    user_ids = {e.user_id for e in events.items}
    user_map = {u.id: u for u in User.query.filter(User.id.in_(user_ids)).all()} if user_ids else {}

    hostname_names = {e.hostname for e in events.items if e.hostname}
    hostname_map = {h.name: h for h in Hostname.query.filter(Hostname.name.in_(hostname_names)).all()} if hostname_names else {}

    # Dropdown choices
    all_users = User.query.order_by(User.username).all() if current_user.is_admin else []
    if current_user.is_admin:
        all_hostnames = Hostname.query.order_by(Hostname.name).all()
    else:
        all_hostnames = Hostname.query.filter_by(user_id=current_user.id).order_by(Hostname.name).all()

    return render_template('events/list.html', events=events, username_filter=username_filter,
                           hostname_filter=hostname_filter, user_map=user_map, hostname_map=hostname_map,
                           all_users=all_users, all_hostnames=all_hostnames)


@web_bp.route('/admin/events/clear', methods=['POST'])
@login_required
@admin_required
def event_clear():
    count = Event.query.delete()
    db.session.commit()
    flash(f'Deleted {count} event(s).', 'success')
    return redirect(url_for('web.event_list'))


# --- Profile (Self-service) ---

@web_bp.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        if not bcrypt.checkpw(form.current_password.data.encode('utf8'), current_user.password_hash.encode()):
            flash('Current password is incorrect.', 'danger')
        else:
            current_user.password_hash = bcrypt.hashpw(form.new_password.data.encode('utf8'), bcrypt.gensalt()).decode()
            db.session.commit()
            flash('Password changed successfully.', 'success')
            return redirect(url_for('web.profile'))
    user_hostnames = Hostname.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', form=form, user_hostnames=user_hostnames,
                           has_totp=current_user.has_totp)


@web_bp.route('/admin/profile/reset-2fa', methods=['POST'])
@login_required
def totp_reset_self():
    password = request.form.get('current_password', '')
    if not bcrypt.checkpw(password.encode('utf8'), current_user.password_hash.encode()):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('web.profile'))
    current_user.set_totp_secret(None)
    db.session.commit()
    flash('Two-factor authentication has been reset. You will set up 2FA on next login.', 'success')
    return redirect(url_for('web.profile'))


@web_bp.route('/admin/users/<int:user_id>/reset-2fa', methods=['POST'])
@login_required
@admin_required
def user_reset_totp(user_id):
    user = User.query.get_or_404(user_id)
    user.set_totp_secret(None)
    db.session.commit()
    flash(f'Two-factor authentication reset for "{user.username}".', 'success')
    return redirect(url_for('web.user_edit', user_id=user.id))


# --- Help ---

@web_bp.route('/admin/help')
@login_required
def help_page():
    return render_template('help.html')
