import base64
import hmac
import hashlib
import secrets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec


def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    return stored_password == provided_password


def generate_session_key(password_hash, nonce):
    """使用AES生成会话密钥"""
    key = hmac.new(password_hash.encode(), nonce.encode(), hashlib.sha256).digest()[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(secrets.token_bytes(16)))
    encryptor = cipher.encryptor()
    session_key = encryptor.update(nonce.encode()) + encryptor.finalize()
    return session_key.hex()


def generate_derived_key(client_public_key_pem, server_private_key):
    """派生对称密钥"""
    client_public_key = serialization.load_pem_public_key(
        client_public_key_pem.encode("utf-8")
    )
    # print(client_public_key_pem.encode("utf-8"))

    # 使用服务端私钥和客户端公钥计算共享密钥
    shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
    shared_key_base64 = base64.b64encode(shared_key).decode("utf-8")
    # print("Shared Key (Base64):", shared_key_base64)

    # 使用 HKDF 派生对称密钥
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 生成 256 位对称密钥
        salt=None,
        info=b"register session",
    ).derive(shared_key)

    return derived_key


def get_encrypted_qr(padded_img_data, symmetric_key):
    """生成iv并加密QR码图片"""
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_qr_code = encryptor.update(padded_img_data) + encryptor.finalize()

    return encrypted_qr_code, iv
