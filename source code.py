import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib
import sys
import os

def resource_path(relative_path):
    # Get absolute path to resource, works for dev and PyInstaller bundle
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def generate_key(password):
    fixed_key = b'_XvGf3r9sF2Hv-C2DqJ2xbN3_GKhzK16xkXOHjhw2Po='  # Valid Fernet key (32 bytes base64)
    if not password:
        return fixed_key
    else:
        password_bytes = password.encode()
        key = hashlib.sha256(password_bytes).digest()
        return base64.urlsafe_b64encode(key)

def encrypt_text():
    text = input_text.get("1.0", tk.END).strip()
    password = password_entry.get() if password_var.get() else ""
    if not text:
        messagebox.showwarning("Warning", "Please enter text to encrypt.")
        return
    try:
        key = generate_key(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(text.encode())
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted.decode())
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_text():
    encrypted_text = output_text.get("1.0", tk.END).strip()
    password = password_entry.get() if password_var.get() else ""
    if not encrypted_text:
        messagebox.showwarning("Warning", "Please enter text to decrypt.")
        return
    try:
        key = generate_key(password)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_text.encode())
        input_text.delete("1.0", tk.END)
        input_text.insert(tk.END, decrypted.decode())
    except (InvalidToken, Exception):
        input_text.delete("1.0", tk.END)
        input_text.insert(tk.END, "nothing")

def save_encrypted_text():
    encrypted_content = output_text.get("1.0", tk.END).strip()
    if not encrypted_content:
        messagebox.showwarning("Warning", "There is no encrypted text to save.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        title="Save Encrypted Text As"
    )
    if file_path:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(encrypted_content)
            messagebox.showinfo("Saved", f"Encrypted text saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file:\n{e}")

root = tk.Tk()
root.title("Launchs Encryption")

# Set the icon using resource_path for PyInstaller compatibility
try:
    root.iconbitmap(resource_path("icon.ico"))
except:
    pass

# Left Input Text
input_label = tk.Label(root, text="Input Text (Plain / Decrypted):")
input_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
input_text = tk.Text(root, width=60, height=20, bd=2, relief="solid")
input_text.grid(row=1, column=0, padx=10, pady=5)

# Right Output Text
output_label = tk.Label(root, text="Output Text (Encrypted / To Decrypt):")
output_label.grid(row=0, column=1, padx=10, pady=5, sticky="w")
output_text = tk.Text(root, width=60, height=20, bd=2, relief="solid")
output_text.grid(row=1, column=1, padx=10, pady=5)

# Password checkbox and entry
password_var = tk.BooleanVar()
password_check = tk.Checkbutton(root, text="Encrypted text requires password", variable=password_var)
password_check.grid(row=2, column=0, padx=10, sticky="w")

password_label = tk.Label(root, text="Password:")
password_label.grid(row=3, column=0, padx=10, sticky="w")
password_entry = tk.Entry(root, show="*", width=30)
password_entry.grid(row=4, column=0, padx=10, sticky="w")

# Buttons
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text, width=20)
encrypt_button.grid(row=5, column=0, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text, width=20)
decrypt_button.grid(row=5, column=1, padx=10, pady=10)

save_button = tk.Button(root, text="Save Encrypted Text", command=save_encrypted_text, width=20)
save_button.grid(row=6, column=1, padx=10, pady=(0, 10))

root.mainloop()
