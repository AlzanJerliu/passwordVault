import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid  # for recovery key
import base64
import pyperclip  #
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryption_key = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    """

    :param message:
    :param key:
    :return:
    """
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# Database
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL, 
recovery_key TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")


# create PopUp
def pop_Up(text):
    answer = simpledialog.askstring("input string", text)
    return answer


#Window
window = Tk()
window.update()
window.title("Password Vault")


def hash_password(input):
    hash1 = hashlib.sha256(input)
    hash1 = hash1.hexdigest()

    return hash1


def first_time_screen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("300x150")

    lbl = Label(window, text="Choose a master password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter Password")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()

    def save_password():
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"  # to delete the old master password when we create a new one
            cursor.execute(sql)
            hashed_password = hash_password(txt.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recovery_key = hash_password(key.encode('utf-8'))

            global encryption_key
            encryption_key = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recovery_key)
            VALUES(?, ?)"""
            cursor.execute(insert_password, (hashed_password, recovery_key))
            db.commit()

            recovery_screen(key)
        else:
            lbl.config(text="Passwords do not match", fg="red")

    btn = Button(window, text="Save", command=save_password)
    btn.pack(pady=5)


def recovery_screen(key):
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("300x150")

    lbl = Label(window, text="Save this key to be able to recover account")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def copy_key():
        pyperclip.copy(lbl1.cget("text"))

    copy_key_btn = Button(window, text="Copy key", command=copy_key)
    copy_key_btn.pack(pady=5)

    def done():
        password_vault()

    done_btn = Button(window, text="Done", command=done)
    done_btn.pack(pady=5)


def reset_screen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("300x150")

    lbl = Label(window, text="Enter recovery key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def get_recovery_key():
        recovery_key_check = hash_password(str(txt.get()).encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id=1 AND recovery_key = ?', [(recovery_key_check)])
        return cursor.fetchall()

    def check_recovery_key():
        checked = get_recovery_key()
        if checked:
            first_time_screen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text='Wrong key', fg="red")

    check_btn = Button(window, text="Check key", command=check_recovery_key)
    check_btn.pack(pady=5)


def login_screen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("300x150")

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl.config(anchor=CENTER)
    lbl1.pack(side=TOP)

    def get_master_password():
        check_hashed_password = hash_password(txt.get().encode('utf-8'))
        global encryption_key
        encryption_key = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(check_hashed_password)])
        print(check_hashed_password)
        return cursor.fetchall()

    def check_password():
        match = get_master_password()

        if match:
            password_vault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong password", fg="red")

    def reset_password():
        reset_screen()

    check_password_btn = Button(window, text="Submit", command=check_password)
    check_password_btn.pack(pady=5)
    reset_password_btn = Button(window, text="Reset password", command=reset_password)
    reset_password_btn.pack(pady=5)


def password_vault():
    for widget in window.winfo_children():
        widget.destroy()

    def add_entry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = encrypt(pop_Up(text1).encode(), encryption_key)
        username = encrypt(pop_Up(text2).encode(), encryption_key)
        password = encrypt(pop_Up(text3).encode(), encryption_key)

        insert_fields = """INSERT INTO vault(website,username,password)
        VALUES(?,?,?)"""
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        password_vault()

    def remove_entry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        password_vault()

    window.geometry("700x550")
    window.resizable(height=None, width=None)
    lbl = Label(window, text="Password Vault")
    lbl.grid(column=1)

    btn = Button(window, text="Add user", command=add_entry)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute('SELECT * FROM vault')  # every time after this command you have to execute fetchall
    if (cursor.fetchall() != None):
        i = 0

        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            lbl1 = Label(window, text=(decrypt(array[i][1], encryption_key)), font=("Helvetica", 12))
            lbl1.grid(column=0, row=i + 3)
            lbl2 = Label(window, text=(decrypt(array[i][2], encryption_key)), font=("Helvetica", 12))
            lbl2.grid(column=1, row=i + 3)
            lbl3 = Label(window, text=(decrypt(array[i][3], encryption_key)), font=("Helvetica", 12))
            lbl3.grid(column=2, row=i + 3)

            remove_btn = Button(window, text="Delete", command=partial(remove_entry, array[i][0]))
            remove_btn.grid(column=3, row=i + 3, pady=10)

            i = i + 1
            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break


cursor.execute('SELECT * FROM masterpassword')
if cursor.fetchall():
    login_screen()
else:
    first_time_screen()
window.mainloop()
