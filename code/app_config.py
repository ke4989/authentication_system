import os
import secrets
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def flask_init():
    app = Flask(__name__)
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per day", "20 per hour"],
    )
    base_dir = os.path.abspath(os.path.dirname(__file__))
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"sqlite:///{os.path.join(base_dir, 'users.db')}"
    )
    secret_key = secrets.token_hex(16)
    app.config["SECRET_KEY"] = secret_key
    app.config["CACHE_TYPE"] = "SimpleCache"  # 使用内存缓存
    app.config["SESSION_PERMANENT"] = False
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db = SQLAlchemy(app)
    cache = Cache(app)
    # Session(app)
    CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:*"}})
    # CORS(app, resources={r"/*": {"origins": "*"}})
    # CORS(
    #     app,
    #     resources={
    #         r"/dh_init": {"origins": "http://127.0.0.1:*"},
    #         r"/register": {"origins": "http://127.0.0.1:*"},
    #         r"/commit": {"origins": "http://127.0.0.1:*"},
    #         r"/login": {"origins": "http://127.0.0.1:*"},
    #     },
    # )
    return app, db, cache, limiter
