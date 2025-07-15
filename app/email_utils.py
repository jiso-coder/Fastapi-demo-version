import random

def generate_otp():
    return str(random.randint(100000, 999999))

def send_email(to_email: str, otp: str):
    print(f"[MOCK EMAIL] To: {to_email} | Your OTP is: {otp}")
