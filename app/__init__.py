from flask import Flask

def create_app():
    app = Flask(__name__)

    from .routes.routes import temp_blueprint
    app.register_blueprint(temp_blueprint)

    return app

