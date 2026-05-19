"""Flask application factory."""

from flask import Flask

from app.database import init_db


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "qsbac-dev-change-in-production"
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    init_db()

    from app.routes import bp

    app.register_blueprint(bp)
    return app
