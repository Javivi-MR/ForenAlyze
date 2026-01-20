from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from ..extensions import db, login_manager
from ..models import User
from app.services.logs import log_event
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign in')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            # Registro de inicio de sesión exitoso
            log_event(
                action="login",
                message="User logged in successfully.",
                status="success",
                resource="auth.login",
                user=user,
                extra={
                    "username": user.username,
                },
            )
            return redirect(url_for('dashboard.dashboard_index'))

        # Intento de login fallido
        log_event(
            action="login_failed",
            message="Failed login attempt.",
            status="failed",
            resource="auth.login",
            extra={
                "username": form.username.data,
            },
        )
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    # Registramos el cierre de sesión antes de invalidar la sesión
    log_event(
        action="logout",
        message="User logged out.",
        status="success",
        resource="auth.logout",
    )
    logout_user()
    return redirect(url_for('auth.login'))
