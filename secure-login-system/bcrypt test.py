import bcrypt
password = b"test123"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())

print("Hashed password:", hashed)