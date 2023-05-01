import os
from flask import Flask, render_template, request, redirect, url_for, abort, session
from flask_admin import Admin, AdminIndexView
from flask_babelex import Babel
from flask_admin.contrib.sqla import ModelView
from functools import wraps
from flask_login import LoginManager, current_user, login_required, login_user
from config import user_db, password_db, host_db, port_db, name_db, secret_key
from config import db
from models import User, UserAdminView

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.secret_key = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{user_db}:{password_db}@{host_db}:{port_db}/{name_db}'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['BABEL_DEFAULT_LOCALE'] = 'ru'
db.init_app(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
babel = Babel(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or current_user.privilege != 'admin':
            abort(403)
        return func(*args, **kwargs)
    return decorated_view


# class MyAdminIndexView(AdminIndexView):
#     @admin_required
#     def is_accessible(self):
#         return is_admin()


admin = Admin(app, name='Панель управления', static_url_path='admin', template_mode='bootstrap3')
admin.add_view(UserAdminView(session=db.session, model=User))


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(username, password)
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            login_user(user)
            if current_user.privilege == 'admin':
                return redirect(url_for('admin.index'))
            else:
                return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return 'dashboard'


@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.index')


if __name__ == '__main__':
    app.run(debug=True)
