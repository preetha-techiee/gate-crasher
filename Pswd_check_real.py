import bcrypt
import re
import hashlib

def check_password_strength(password):
    # Length check
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    
    # Complexity check (using regular expressions)
    if not re.search(r'[a-z]', password):  # lowercase
        return "Password must contain at least one lowercase letter."
    if not re.search(r'[A-Z]', password):  # uppercase
        return "Password must contain at least one uppercase letter."
    if not re.search(r'\d', password):  # digit
        return "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  # special character
        return "Password must contain at least one special character."
    
    # Common password check (for example, using a basic common password list)
    common_passwords = ["123456", "password", "qwerty", "abc123"]
    if password in common_passwords:
        return "This password is too common, try a more unique one."

    # Hash the password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    pswd = hashlib.sha256(password.encode()).hexdigest()
    return f"Password is strong!\nHashed value: {hashed}\nThe sha 256 code is: {pswd}"

# Example Usage
password = input("Enter a password: ")
feedback = check_password_strength(password)
print(feedback)
