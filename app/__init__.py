from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

# load environment variables from .env
load_dotenv()

# Initialize extensions globally
db = SQLAlchemy()
jwt = JWTManager()

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day, 50 per hour"])

def create_app():
    app = Flask(__name__)

    #Config setup
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
    app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    #Init Extensions
    db.init_app(app)
    jwt.init_app(app)

    #Import routes and register blueprints
    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')

    return app