from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.padding import PKCS7


def pad_data(data, block_size=128):  # 128位块大小
    padder = PKCS7(block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def generate_dh_keys():
    # 生成 DH 参数和服务端密钥对
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()
    server_public_key_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # cache.set("temp_key", server_public_key_pem, timeout=300)
    # print(server_public_key)
    return server_private_key, server_public_key_pem


def generate_ec_keys():
    # 生成 EC 参数和服务端密钥对
    server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_public_key = server_private_key.public_key()
    # 将公钥转换为 PEM 格式的字符串
    server_public_key_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # print(server_public_key_pem)
    return server_private_key, server_public_key_pem
