from datetime import datetime
from flask_login import UserMixin
from flask_admin.contrib.sqla import ModelView
from wtforms import StringField, PasswordField, SelectField, Form
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from flask_babelex import lazy_gettext
from wtforms.validators import Length
from flask_admin.form import Select2Widget
from wtforms import StringField, SelectField, PasswordField
from wtforms.validators import DataRequired
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from config import db


class User(db.Model, UserMixin):
    __tablename__ = 'user_bi'

    id = db.Column(db.Integer, primary_key=True, verbose_name='ID пользователя')
    user_id = db.Column(db.Integer, nullable=False, unique=True,  verbose_name='ID пользователя')
    username = db.Column(db.String(50), nullable=False, unique=True, verbose_name='Имя пользователя')
    password = db.Column(db.String(128), nullable=False, verbose_name='Пароль пользователя')
    privilege = db.Column(db.String(100), nullable=False, verbose_name='Роль пользователя')
    created_at = db.Column(db.DateTime(), default=datetime.utcnow, verbose_name='Время создания')

    def __init__(self, username, password, privilege, user_id=None):
        self.username = username
        self.user_id = user_id
        self.privilege = privilege
        self.set_password(password)

    def set_password(self, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = Fernet(base64.urlsafe_b64encode(kdf.derive(os.getenv('SECRET_KEY').encode())))
        password_bytes = password.encode('utf-8')
        encrypted_password_bytes = key.encrypt(password_bytes)
        self.password = base64.urlsafe_b64encode(salt + encrypted_password_bytes).decode('ascii')

    def check_password(self, password):
        salted_password_bytes = base64.urlsafe_b64decode(self.password.encode())
        salt = salted_password_bytes[:16]
        encrypted_password_bytes = salted_password_bytes[16:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = Fernet(base64.urlsafe_b64encode(kdf.derive(os.getenv('SECRET_KEY').encode())))
        decrypted_password_bytes = key.decrypt(encrypted_password_bytes)
        return decrypted_password_bytes.decode('utf-8') == password

    @property
    def clear_password(self):
        salted_password_bytes = base64.urlsafe_b64decode(self.password.encode())
        salt = salted_password_bytes[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = Fernet(base64.urlsafe_b64encode(kdf.derive(os.getenv('SECRET_KEY').encode())))
        salted_password_bytes = base64.urlsafe_b64decode(self.password.encode())
        salt = salted_password_bytes[:16]
        encrypted_password_bytes = salted_password_bytes[16:]
        decrypted_password_bytes = key.decrypt(encrypted_password_bytes)
        return decrypted_password_bytes.decode('utf-8')

    def save(self):
        db.session.add(self)
        db.session.commit()

    @property
    def verbose_name(self):
        return lazy_gettext('Пользователи')


class UserForm(Form):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    privilege = SelectField('Privilege', choices=[('admin', 'admin'), ('user', 'user')], widget=Select2Widget())


class UserAdminView(ModelView):
    model = User
    column_display_pk = False
    form = UserForm
    column_list = ('id', 'username', 'clear_password', 'privilege')
    column_labels = dict(id='ID', username='Имя пользователя', clear_password='Пароль', privilege='Роль')
    form_args = {
        'username': {
            'validators': [Length(min=3, message='Имя пользователя должно быть не короче 3 символов')],
        },
        'password': {
            'validators': [Length(min=6, message='Пароль должен быть длиннее 6 символов')],
        },
    }
    column_searchable_list = ('username', 'privilege')

    def on_model_create(self, form, model, is_created):
        user = User(username=form.username.data, password=form.password.data, privilege=form.privilege.data)
        user.save()

    def on_model_change(self, form, model, is_created):
        if form.password.data:
            model.set_password(form.password.data)
        model.save()
