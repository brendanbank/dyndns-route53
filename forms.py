from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Optional, ValidationError
from models import User


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=80)])
    password = PasswordField('Password', validators=[Optional(), Length(min=8)])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Save')

    def __init__(self, original_username=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_username = original_username

    def validate_username(self, field):
        if field.data != self._original_username:
            if User.query.filter_by(username=field.data).first():
                raise ValidationError('Username already exists.')


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')

    def validate_confirm_password(self, field):
        if field.data != self.new_password.data:
            raise ValidationError('Passwords do not match.')


class TOTPVerifyForm(FlaskForm):
    code = StringField('Authentication Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')


class TOTPSetupForm(FlaskForm):
    code = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Enable 2FA')


class DomainForm(FlaskForm):
    name = StringField('Domain Name', validators=[DataRequired(), Length(max=255)])
    submit = SubmitField('Save')


class HostnameForm(FlaskForm):
    prefix = StringField('Hostname Prefix', validators=[DataRequired(), Length(max=255)])
    domain_id = SelectField('Domain', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Add Hostname')
