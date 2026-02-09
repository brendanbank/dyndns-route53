import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me-in-production')
    FERNET_KEY = os.environ.get('FERNET_KEY')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'instance', 'dyndns.db')
    SQLALCHEMY_BINDS = {
        'events': 'sqlite:///' + os.path.join(basedir, 'instance', 'events.db'),
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'connect_args': {'timeout': 30},
    }
    WTF_CSRF_ENABLED = True
