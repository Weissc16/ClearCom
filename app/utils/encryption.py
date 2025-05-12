from cryptography.fernet import Fernet

#Use a secure, environment-stored key in production
FERNET_KEY = b'lJNp60SnsOWYpzqpmLi-0FM8P5JWogf6j9mWQWsczKQ='

cipher = Fernet(FERNET_KEY)

def encrypt_message(message):
    return cipher.encrypt(message.encode()).decode()

def decrypt_message(token):
    return cipher.decrypt(token.encode()).decode()