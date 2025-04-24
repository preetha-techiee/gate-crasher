import tkinter as tk
from tkinter import messagebox
import bcrypt
import re
import hashlib
from cryptography.fernet import Fernet

# Generate key (you can also save/load this from a secure file)
fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)

def copy_to_clipboard(text):
    window.clipboard_clear()
    window.clipboard_append(text)
    messagebox.showinfo("Copied!", "Hash copied to clipboard!")

def check_password_strength():
    password = entry.get()
    score = 0

    if len(password) >= 8:
        score += 1
    else:
        result.set("❌ Must be at least 8 characters.")
        update_strength_bar(score)
        return
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    if password in ["123456", "password", "qwerty", "abc123"]:
        result.set("❌ This password is too common.")
        update_strength_bar(score)
        return

    # Hashing
    bcrypt_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode()
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()

    result.set(f"✅ Password is strong!\n🔒 Bcrypt: {bcrypt_hash}\n🔐 SHA-256: {sha256_hash}")
    update_strength_bar(score)

    # Save encrypted password
    encrypted_pw = cipher.encrypt(password.encode())
    with open("saved_passwords.enc", "ab") as f:
        f.write(encrypted_pw + b"\n")

    # Enable copy buttons
    copy_bcrypt.config(state=tk.NORMAL, command=lambda: copy_to_clipboard(bcrypt_hash))
    copy_sha256.config(state=tk.NORMAL, command=lambda: copy_to_clipboard(sha256_hash))

def update_strength_bar(score):
    colors = ["red", "orange", "yellow", "light green", "green"]
    bar.config(bg=colors[score-1] if score > 0 else "gray")
    bar_label.config(text=f"Strength: {score}/5")

# GUI Setup
window = tk.Tk()
window.title("Password Strength Checker Pro 🔐")
window.geometry("600x400")

tk.Label(window, text="Enter your password:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(window, show="*", width=40, font=("Arial", 12))
entry.pack()

tk.Button(window, text="Check Strength", command=check_password_strength).pack(pady=10)

result = tk.StringVar()
tk.Label(window, textvariable=result, wraplength=550, justify="left", font=("Courier", 10)).pack(pady=10)

# Copy Buttons
copy_bcrypt = tk.Button(window, text="📋 Copy Bcrypt", state=tk.DISABLED)
copy_sha256 = tk.Button(window, text="📋 Copy SHA-256", state=tk.DISABLED)
copy_bcrypt.pack(pady=2)
copy_sha256.pack(pady=2)

# Strength Meter Bar
bar_label = tk.Label(window, text="Strength: 0/5", font=("Arial", 10))
bar_label.pack()
bar = tk.Frame(window, width=200, height=20, bg="gray")
bar.pack(pady=5)

window.mainloop()
