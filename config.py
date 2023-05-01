import os
from dotenv import load_dotenv, find_dotenv
from flask_sqlalchemy import SQLAlchemy
import secrets
from hashlib import sha256


load_dotenv(find_dotenv())
db = SQLAlchemy()

secret_key = secrets.token_hex(16)
user_db = os.getenv('USER_DB')
password_db = os.getenv('PASSWORD_DB')
host_db = os.getenv('HOST_DB')
port_db = os.getenv('PORT_DB')
name_db = os.getenv('NAME_DB')
