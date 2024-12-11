import os
import time
import random
import pyotp
import qrcode  # qrcode[pil]


def get_otp(user_name, web_name):
    secret = pyotp.random_base32()
    # totp = pyotp.TOTP(secret)
    url = pyotp.totp.TOTP(secret).provisioning_uri(name=user_name, issuer_name=web_name)
    return secret, url


def get_opt_image(user_name, web_name):
    secret, image_url = get_otp(user_name, web_name)
    # Generate OTP QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(image_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    return secret, img


def verify_otp(secret, otp_password):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp_password)


def main():
    otp_secret, qr_img = get_opt_image("L", "502C Secuirty")
    print(len(otp_secret))
    print(otp_secret)
    qr_code_path = f"{otp_secret}.png"
    # os.makedirs(os.path.dirname(qr_code_path), exist_ok=True)
    qr_img.save(qr_code_path)


if __name__ == "__main__":
    main()
    # is_right = verify_otp("PU4YWW4TDRCUJOLUN7BLLOR3LCBFIS6R", "078221")
    # print(is_right)
