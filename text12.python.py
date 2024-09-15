import random
import string
import tkinter as tk
from tkinter import messagebox
from hashlib import sha256
from base64 import b64encode
from cryptography.fernet import Fernet
from PIL import Image, ImageTk

def generate_key():
    arabic_chars = 'أبجد هوز حطي كلمن سعفص قرشت ثخذ ضظغ'
    all_chars = string.ascii_letters + string.digits + string.punctuation + arabic_chars
    all_chars = list(all_chars)
    key = all_chars.copy()
    random.shuffle(key)
    return all_chars, key

def generate_fernet_key(password):
    password_hash = sha256(password.encode()).digest()
    return Fernet(b64encode(password_hash[:32]))

def encrypt_message(plain_text, all_chars, key):
    cipher_text = ""
    for letter in plain_text:
        if letter in all_chars:
            index = all_chars.index(letter)
            cipher_text += key[index]
        else:
            cipher_text += letter
    return cipher_text

def decrypt_message(cipher_text, all_chars, key):
    plain_text = ""
    for letter in cipher_text:
        if letter in key:
            index = key.index(letter)
            plain_text += all_chars[index]
        else:
            plain_text += letter
    return plain_text

def encrypt():
    plain_text = entry_plain.get("1.0", tk.END).strip()
    password = entry_password.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password.")
        return
    if not plain_text:
        messagebox.showwarning("Warning", "Please enter text to encrypt.")
        return
    cipher_text = encrypt_message(plain_text, all_chars, key)
    fernet = generate_fernet_key(password)
    encrypted_key = fernet.encrypt(''.join(key).encode()).decode()
    entry_cipher.delete("1.0", tk.END)
    entry_cipher.insert("1.0", cipher_text)
    entry_encrypted_key.delete("1.0", tk.END)
    entry_encrypted_key.insert("1.0", encrypted_key)

def decrypt():
    cipher_text = entry_cipher.get("1.0", tk.END).strip()
    encrypted_key = entry_encrypted_key.get("1.0", tk.END).strip()
    password = entry_password.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password.")
        return
    if not cipher_text or not encrypted_key:
        messagebox.showwarning("Warning", "Please enter the encrypted text and key.")
        return
    try:
        fernet = generate_fernet_key(password)
        decrypted_key = fernet.decrypt(encrypted_key.encode()).decode()
        key = list(decrypted_key)
        plain_text = decrypt_message(cipher_text, all_chars, key)
        entry_plain.delete("1.0", tk.END)
        entry_plain.insert("1.0", plain_text)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def clear_text():
    entry_plain.delete("1.0", tk.END)
    entry_cipher.delete("1.0", tk.END)
    entry_encrypted_key.delete("1.0", tk.END)
    entry_password.delete(0, tk.END)

def load_image(file_path):
    try:
        image = Image.open(file_path)
        image = image.resize((root.winfo_screenwidth(), root.winfo_screenheight()), Image.LANCZOS)
        return ImageTk.PhotoImage(image)
    except FileNotFoundError:
        print(f"Error: Image file not found: {file_path}")
        return None

def load_icon(file_path, size=(24, 24)):
    try:
        image = Image.open(file_path)
        image = image.resize(size, Image.LANCZOS)
        return ImageTk.PhotoImage(image)
    except FileNotFoundError:
        print(f"Error: Icon file not found: {file_path}")
        return None

root = tk.Tk()
root.title("Encryption/Decryption Tool")

all_chars, key = generate_key()

background_image = load_image(r"C:\Users\HP\Desktop\kgt\2222.jfif") 
if background_image:
    background_label = tk.Label(root, image=background_image)
    background_label.place(relwidth=1, relheight=1)

icon_path = r"C:\Users\HP\Desktop\kgt\1111.jfif"  
icon_image = load_icon(icon_path)

frame = tk.Frame(root)
frame.grid(row=0, column=0, padx=20, pady=20, sticky='nsew')

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)
frame.grid_rowconfigure(5, weight=1)
frame.grid_columnconfigure(1, weight=1)

label_font = ('Helvetica', 12)
entry_font = ('Helvetica', 14)
text_height = 6

tk.Label(frame, text="Enter your message:", fg='#000000', font=label_font).grid(row=0, column=0, padx=10, pady=10, sticky='e')
entry_plain = tk.Text(frame, width=60, height=text_height, font=entry_font, bg='#FFFFF0', fg='#000000', bd=1, padx=5, pady=5)
entry_plain.grid(row=0, column=1, padx=10, pady=10)

tk.Label(frame, text="Encrypted message:", fg='#000000', font=label_font).grid(row=1, column=0, padx=10, pady=10, sticky='e')
entry_cipher = tk.Text(frame, width=60, height=text_height, font=entry_font, bg='#FFFFF0', fg='#000000', bd=1, padx=5, pady=5)
entry_cipher.grid(row=1, column=1, padx=10, pady=10)

tk.Label(frame, text="Encrypted key:", fg='#000000', font=label_font).grid(row=2, column=0, padx=10, pady=10, sticky='e')
entry_encrypted_key = tk.Text(frame, width=60, height=text_height, font=entry_font, bg='#FFFFF0', fg='#000000', bd=1, padx=5, pady=5)
entry_encrypted_key.grid(row=2, column=1, padx=10, pady=10)

tk.Label(frame, text="Password:", fg='#000000', font=label_font).grid(row=3, column=0, padx=10, pady=10, sticky='e')
entry_password = tk.Entry(frame, width=80, font=entry_font, show='*', bg='#FFFFF0', fg='#000000', bd=1)
entry_password.grid(row=3, column=1, padx=10, pady=10)

button_font = ('Helvetica', 12)
button_bg = '#57707a'
button_fg = '#FFFFFF'  

button_options = {
    'font': button_font,
    'bg': button_bg,
    'fg': button_fg,
    'relief': 'flat',
    'image': icon_image,
    'compound': 'left',
    'padx': 10,
    'pady': 5
}

tk.Button(frame, text="Encrypt", command=encrypt, **button_options).grid(row=4, column=0, padx=10, pady=10, sticky='e')
tk.Button(frame, text="Decrypt", command=decrypt, **button_options).grid(row=4, column=1, padx=10, pady=10, sticky='w')
tk.Button(frame, text="Clear", command=clear_text, **button_options).grid(row=5, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()
