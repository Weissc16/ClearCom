from flask import Flask
from app.extensions import db, migrate, limiter
from config import Config  # adjust if you use a different config
from flask_jwt_extended import JWTManager

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    jwt = JWTManager(app)

    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')

    return app
