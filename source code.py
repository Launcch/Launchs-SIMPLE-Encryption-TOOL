import tkinter as tk
from tkinter import ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import sys

# === CONSTANT NO-PASSWORD KEY (fixed for consistent encrypt/decrypt) ===
NO_PASSWORD_KEY = b'4gFZx6ArQ5KydOxqW3hI_P8pGVwWXWm53jr5hLgB_W8='  # <-- generated once and hardcoded here
fernet_no_password = Fernet(NO_PASSWORD_KEY)

# Derive a Fernet key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Helper for loading resources correctly with PyInstaller
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def encrypt():
    input_text = input_textbox.get("1.0", tk.END).strip()
    use_password = password_check_var.get()
    password = password_entry.get() if use_password else None

    if not input_text:
        output_textbox.delete("1.0", tk.END)
        output_textbox.insert(tk.END, "Error: No input text to encrypt.")
        return

    if use_password:
        if not password:
            output_textbox.delete("1.0", tk.END)
            output_textbox.insert(tk.END, "Error: Password required.")
            return
        salt = os.urandom(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(input_text.encode())
        result = base64.urlsafe_b64encode(salt + encrypted).decode()
    else:
        encrypted = fernet_no_password.encrypt(input_text.encode())
        result = encrypted.decode()

    output_textbox.delete("1.0", tk.END)
    output_textbox.insert(tk.END, result)

def decrypt():
    encrypted_text = output_textbox.get("1.0", tk.END).strip()
    use_password = password_check_var.get()
    password = password_entry.get() if use_password else None

    if not encrypted_text:
        input_textbox.delete("1.0", tk.END)
        input_textbox.insert(tk.END, "Error: No encrypted text to decrypt.")
        return

    try:
        if use_password:
            if not password:
                input_textbox.delete("1.0", tk.END)
                input_textbox.insert(tk.END, "Error: Password required.")
                return
            data = base64.urlsafe_b64decode(encrypted_text.encode())
            salt = data[:16]
            encrypted = data[16:]
            key = derive_key(password, salt)
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted).decode()
        else:
            decrypted = fernet_no_password.decrypt(encrypted_text.encode()).decode()

        input_textbox.delete("1.0", tk.END)
        input_textbox.insert(tk.END, decrypted)
    except Exception as e:
        if "Fernet key must be 32 url-safe base64-encoded bytes" in str(e):
            input_textbox.delete("1.0", tk.END)
            input_textbox.insert(tk.END, "nothing")
        else:
            input_textbox.delete("1.0", tk.END)
            input_textbox.insert(tk.END, f"Decryption failed: {str(e)}")

root = tk.Tk()
root.title("Launchs Encryption")

# Load icon with PyInstaller support
icon_path = resource_path("icon.ico")
try:
    root.iconbitmap(icon_path)
except Exception as e:
    print(f"Warning: Could not load icon: {e}")

# Left input textbox
input_frame = ttk.Frame(root)
input_frame.grid(row=0, column=0, padx=10, pady=10)

ttk.Label(input_frame, text="Input Text").pack()
input_textbox = tk.Text(input_frame, width=40, height=15, highlightthickness=1, highlightbackground="black")
input_textbox.pack()
encrypt_button = ttk.Button(input_frame, text="Encrypt", command=encrypt)
encrypt_button.pack(pady=5)

# Right output textbox
output_frame = ttk.Frame(root)
output_frame.grid(row=0, column=1, padx=10, pady=10)

ttk.Label(output_frame, text="Output Text").pack()
output_textbox = tk.Text(output_frame, width=40, height=15, highlightthickness=1, highlightbackground="black")
output_textbox.pack()
decrypt_button = ttk.Button(output_frame, text="Decrypt", command=decrypt)
decrypt_button.pack(pady=5)

# Password checkbox and entry below text boxes
password_check_var = tk.BooleanVar()
password_check = ttk.Checkbutton(root, text="Encrypted text requires password", variable=password_check_var)
password_check.grid(row=1, column=0, sticky="w", padx=10)

password_entry = ttk.Entry(root, show="*")
password_entry.grid(row=1, column=1, sticky="w", padx=10)
password_entry.config(state="disabled")  # Disabled by default

def toggle_password_entry():
    if password_check_var.get():
        password_entry.config(state="normal")
    else:
        password_entry.delete(0, tk.END)
        password_entry.config(state="disabled")

password_check.config(command=toggle_password_entry)

root.mainloop()


