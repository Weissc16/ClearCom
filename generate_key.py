from cryptography.fernet import Fernet

with open("secret.key", "wb") as f:
    f.write(Fernet.generate_key())


print("Fernet Key generated and saved to secret.key")