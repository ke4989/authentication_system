import os
import secrets
import base64
from io import BytesIO
from PIL import Image
from flask import request, jsonify
from app_config import flask_init, User
from dh import pad_data, generate_ec_keys
from otp import get_opt_image, verify_otp
from util import (
    verify_password,
    generate_derived_key,
    get_encrypted_qr,
)

app, db, cache, limiter = flask_init()


# 创建用户模型，定义数据库结构
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    # public_key = db.Column(db.String(256))
    symmetric_key = db.Column(db.String(256))
    otp_secret = db.Column(db.String(32))


@app.route("/register", methods=["POST", "OPTIONS"])
@limiter.limit("3/minute", override_defaults=False)
def register():
    if request.method == "OPTIONS":
        # 处理预检请求
        return "", 200

    data = request.get_json()
    username = data.get("username")
    password_hash = data.get("password")
    client_public_key_pem = data.get("client_public_key")  # 接收客户端 DH 公钥

    # 验证客户端公钥
    if not client_public_key_pem:
        return jsonify({"error": "Client public key is missing"}), 400

    # 获取加密秘钥
    server_private_key, server_public_key_pem = generate_ec_keys()
    cache.set("temp_key", server_public_key_pem, timeout=300)
    derived_key = generate_derived_key(client_public_key_pem, server_private_key)

    # Generate OTP secret
    otp_secret, qr_img = get_opt_image(username, "Auth")
    img_byte_arr = BytesIO()
    qr_img.save(img_byte_arr, format="PNG")
    # img_byte_arr.seek(0)
    img_data = img_byte_arr.getvalue()
    padded_img_data = pad_data(img_data)

    # 使用公钥加密QR码图片
    symmetric_key = derived_key
    encrypted_qr_code, iv = get_encrypted_qr(padded_img_data, symmetric_key)

    # send_file(img_byte_arr, mimetype="image/png")

    # 检查用户名是否存在，返回信息可根据安全需求修改
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400

    new_user = {
        "username": username,
        "password_hash": password_hash,
        "symmetric_key": symmetric_key,
        "otp_secret": otp_secret,
    }
    # 使用缓存，若直接修改数据库，网页自动刷新，不会显示QR码图片
    cache.set("temp_data", new_user, timeout=300)

    encrypted_img_base64 = base64.b64encode(encrypted_qr_code).decode("utf-8")
    symmetric_key_base64 = base64.b64encode(symmetric_key).decode("utf-8")
    # print(symmetric_key_base64)
    iv_base64 = base64.b64encode(iv).decode("utf-8")

    return (
        jsonify(
            {
                "message": "User registered successfully.",
                "otp_qr_code": encrypted_img_base64,
                "iv": iv_base64,
            }
        ),
        201,
    )


@app.route("/dh_init", methods=["GET"])
@limiter.limit("3/minute", override_defaults=False)
def dh_init():
    """返回服务器的 DH 公钥"""
    server_public_key_pem = cache.get("temp_key")
    server_public_key_base64 = (
        server_public_key_pem.decode("utf-8")
        .replace("-----BEGIN PUBLIC KEY-----\n", "")
        .replace("-----END PUBLIC KEY-----\n", "")
        .replace("\n", "")
    )
    return jsonify({"server_public_key": server_public_key_base64})


@app.route("/commit", methods=["POST"])
@limiter.limit("3/minute", override_defaults=False)
def commit():
    try:
        # 从会话中获取新用户实例
        new_user_data = cache.get("temp_data")
        if not new_user_data:
            return jsonify({"error": "No user to commit"}), 400
        new_user = User(
            username=new_user_data["username"],
            password_hash=new_user_data["password_hash"],
            symmetric_key=new_user_data["symmetric_key"],
            otp_secret=new_user_data["otp_secret"],
        )
        # 添加新用户到数据库会话
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Database commit failed: {str(e)}")
        return jsonify({"error": "Database commit failed"}), 500
    return jsonify({"message": "Commit successful"}), 200


@app.route("/login", methods=["POST"])
@limiter.limit("5/minute", override_defaults=False)
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")  # it's hashed
    otp = data.get("otp")

    user = User.query.filter_by(username=username).first()

    if (
        not user
        or not verify_password(user.password_hash, password)
        or not verify_otp(user.otp_secret, otp)
    ):
        return jsonify({"message": "Invalid credentials."}), 401

    return jsonify({"message": "success"}), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    # app.run(host="0.0.0.0", port=5000, debug=False)
