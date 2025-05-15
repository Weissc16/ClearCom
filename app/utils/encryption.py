from cryptography.fernet import Fernet

#Use a secure, environment-stored key in production
with open("secret.key", "rb") as f:
    key = f.read()

fernet = Fernet(key)

def encrypt_message(message: str) -> str:
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()