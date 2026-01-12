import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'forenhub-secret-key')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///forenhub.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
