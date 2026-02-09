import io
import bcrypt
import pyotp
import qrcode
import qrcode.image.svg
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, UserDomain, BackendConfig, Event, encrypt_value, decrypt_value
from forms import LoginForm, UserForm, PasswordChangeForm, TOTPVerifyForm, TOTPSetupForm
from auth import admin_required, authenticate_dyndns_user

web_bp = Blueprint('web', __name__)

ITEMS_PER_PAGE = 25

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

BACKEND_CONFIG_KEYS = {
    'aws': AWS_CONFIG_KEYS,
    'nsupdate': NSUPDATE_CONFIG_KEYS,
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
        domain_count = UserDomain.query.distinct(UserDomain.domain_name).count()
        event_count = Event.query.count()
        recent_events = Event.query.order_by(Event.created_at.desc()).limit(10).all()
        return render_template('dashboard.html', user_count=user_count, domain_count=domain_count,
                               event_count=event_count, recent_events=recent_events)
    else:
        user_domains = UserDomain.query.filter_by(user_id=current_user.id).all()
        recent_events = Event.query.filter_by(user_id=current_user.id).order_by(Event.created_at.desc()).limit(10).all()
        return render_template('dashboard.html', user_domains=user_domains, recent_events=recent_events)


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
                    role=form.role.data, is_active=form.is_active.data)
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


# --- User Domain Management (Admin) ---

@web_bp.route('/admin/users/<int:user_id>/domains', methods=['GET', 'POST'])
@login_required
@admin_required
def user_domains(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        domain_name = request.form.get('domain_name', '').strip().lower()
        backend_type = request.form.get('backend_type', 'aws')
        if not domain_name:
            flash('Domain name is required.', 'danger')
        elif backend_type not in BACKEND_CONFIG_KEYS:
            flash('Invalid backend type.', 'danger')
        else:
            existing = UserDomain.query.filter_by(
                user_id=user.id, domain_name=domain_name, backend_type=backend_type).first()
            if existing:
                flash(f'"{domain_name}" with backend "{backend_type}" already exists.', 'warning')
            else:
                ud = UserDomain(user_id=user.id, domain_name=domain_name, backend_type=backend_type)
                db.session.add(ud)
                db.session.commit()
                flash(f'Domain "{domain_name}" ({backend_type}) added.', 'success')
        return redirect(url_for('web.user_domains', user_id=user.id))

    user_domain_list = UserDomain.query.filter_by(user_id=user.id).order_by(
        UserDomain.domain_name, UserDomain.backend_type).all()
    return render_template('users/domains.html', user=user, user_domains=user_domain_list)


@web_bp.route('/admin/users/<int:user_id>/domains/<int:ud_id>/delete', methods=['POST'])
@login_required
@admin_required
def user_domain_delete(user_id, ud_id):
    ud = UserDomain.query.get_or_404(ud_id)
    db.session.delete(ud)
    db.session.commit()
    flash('Domain removed.', 'success')
    return redirect(url_for('web.user_domains', user_id=user_id))


# --- Backend Config per Domain (Admin) ---

@web_bp.route('/admin/users/<int:user_id>/domains/<int:ud_id>/config', methods=['GET', 'POST'])
@login_required
@admin_required
def domain_backend_config(user_id, ud_id):
    ud = UserDomain.query.get_or_404(ud_id)
    user = User.query.get_or_404(user_id)

    config_keys = BACKEND_CONFIG_KEYS.get(ud.backend_type)
    if not config_keys:
        flash('Invalid backend type.', 'danger')
        return redirect(url_for('web.user_domains', user_id=user_id))

    existing = {c.config_key: c for c in ud.configs}

    if request.method == 'POST':
        for key, label in config_keys:
            value = request.form.get(key, '').strip()
            if value:
                if key in existing:
                    existing[key].config_value = encrypt_value(value)
                else:
                    cfg = BackendConfig(user_domain_id=ud.id,
                                        config_key=key, config_value=encrypt_value(value))
                    db.session.add(cfg)
            elif key in existing:
                db.session.delete(existing[key])
        db.session.commit()
        flash(f'Credentials for "{ud.domain_name}" ({ud.backend_type}) updated.', 'success')
        return redirect(url_for('web.domain_backend_config', user_id=user_id, ud_id=ud_id))

    current_values = {}
    for key, label in config_keys:
        if key in existing:
            try:
                current_values[key] = decrypt_value(existing[key].config_value)
            except Exception:
                current_values[key] = ''
        else:
            current_values[key] = ''

    return render_template('backends/edit.html', user=user, ud=ud,
                           config_keys=config_keys, current_values=current_values)


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
        query = query.filter(Event.username.ilike(f'%{username_filter}%'))
    if hostname_filter:
        query = query.filter(Event.hostname.ilike(f'%{hostname_filter}%'))

    events = query.order_by(Event.created_at.desc()).paginate(page=page, per_page=ITEMS_PER_PAGE, error_out=False)
    return render_template('events/list.html', events=events, username_filter=username_filter,
                           hostname_filter=hostname_filter)


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
    user_domains = UserDomain.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', form=form, user_domains=user_domains,
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
