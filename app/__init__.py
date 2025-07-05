from flask import Flask
from app.extensions import db
from flask_migrate import Migrate
import os

# Create an instance of Migrate
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-default-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config.from_object('config.Config')  # or however you load config

    db.init_app(app)
    migrate.init_app(app, db)  # Now 'migrate' is defined
    app.config['DEBUG'] = True
    from app.routes import main
    app.register_blueprint(main)

    @app.shell_context_processor
    def make_shell_context():
        return {'db': db}

    return app
