from flask import Flask
from .config import Config
from .models.extensions import db
from .routes.routes import temp_blueprint
from .routes.userRoutes import user_blueprint
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    jwt = JWTManager(app)

    _register_blueprints(app)

    return app


def _register_blueprints(app):
    app.register_blueprint(temp_blueprint)
    app.register_blueprint(user_blueprint)
