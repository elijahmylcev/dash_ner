from datetime import datetime
from flask_login import UserMixin
from flask_admin.contrib.sqla import ModelView
from wtforms import StringField, PasswordField
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from flask_babelex import lazy_gettext
from wtforms.validators import Length
import secrets
from hashlib import sha256
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
    salt = db.Column(db.String(32), nullable=False, verbose_name='Соль шифровки')

    @property
    def clear_password(self):
        return self.decrypt_password()

    def __init__(self, user_id, username, password, privilege):
        self.username = username
        self.user_id = user_id
        self.privilege = privilege
        self.set_password(password)

    def set_password(self, password):
        self.salt = secrets.token_hex(16)
        self.password = sha256((password + self.salt).encode('utf-8')).hexdigest()

    def check_password(self, password):
        hash_password = sha256((password + self.salt).encode('utf-8')).hexdigest()
        return self.password == hash_password

    def decrypt_password(self):
        salt_bytes = bytes.fromhex(self.salt)
        password_bytes = bytes.fromhex(self.password)
        hashed_password = sha256(password_bytes + salt_bytes).hexdigest()
        key = sha256(hashed_password.encode('utf-8')).digest()
        f = Fernet(key)
        decrypted_password = f.decrypt(password_bytes)
        return decrypted_password.decode('utf-8')

    def save(self):
        db.session.add(self)
        db.session.commit()

    @property
    def verbose_name(self):
        return lazy_gettext('Пользователи')


class UserAdminView(ModelView):
    model = User
    column_display_pk = False  # показывать ID записей в списке
    form_columns = ['username', 'password']  # отображать только указанные поля в форме
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
    form_widget_args = {
        'password': {'type': 'password'}
    }
    column_searchable_list = ('username', 'privilege')
    form_extra_fields = {
        'password': PasswordField('Пароль'),
    }

    # def on_model_change(self, form, model, is_created):
    #     if form.password.data:
    #         model.password = generate_password_hash(form.password.data)
