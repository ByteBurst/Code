#! python3

# Importing necessary libraries and modules that we need for the code to work. 
import tkinter as tk
from tkinter import simpledialog, messagebox
import mysql.connector
import os
from cryptography.fernet import Fernet
import hashlib

# Connecting to the local SQL Database, and also added error handling in case connection fails.
try:
    # Connect to MySQL database, server is localhost
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="DBSokker911!",
        database="passwordvault"
    )
except mysql.connector.Error as err:
    print("Error connecting to database: " + str(err))
    exit()

# Create cursor object for interacting with the database.
cursor = db.cursor()


# Function to hash a password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to check the master password
def check_master_password():
    try:
        # Retrieve the stored master password from the database
        cursor.execute("SELECT master_password_hashed, encryption_key FROM master_password WHERE id = 1")
        result = cursor.fetchone()

        # Check if the result is None
        if result is None:
            # No master password exists, ask the user to create one
            master_password = simpledialog.askstring("Create Master Password", "No master password found. Please create one:", show='*')
            if master_password:
                master_password_hashed = hash_password(master_password)
                
                # Check if an encryption key already exists
                cursor.execute("SELECT encryption_key FROM master_password WHERE id = 1")
                existing_key = cursor.fetchone()
                
                # Use existing key if it exists
                if existing_key:
                    encryption_key = existing_key[0].encode() 
                else:
                    # If there is no encryption key in the database then create one
                    encryption_key = Fernet.generate_key()  
                    cursor.execute("INSERT INTO master_password (id, master_password_hashed, encryption_key) VALUES (1, %s, %s)", (master_password_hashed, encryption_key.decode()))
                    db.commit()
                
                # Messagebox stating that master password was created successfully
                messagebox.showinfo("Success", "Master password created successfully!")

                # Return encryption key
                return encryption_key
            else:
                messagebox.showerror("Error", "Master password creation failed!")
                exit()

        else:
            # Extract stored master password hash and encryption key from the database result
            stored_master_password_hashed, encryption_key = result
            # Convert the encryption key to bytes
            encryption_key = encryption_key.encode()  
            entered_master_password = simpledialog.askstring("Master Password", "Enter the master password:", show='*')
            entered_master_password_hashed = hash_password(entered_master_password)

            # Check if the entered password is correct
            if entered_master_password_hashed == stored_master_password_hashed:
                return encryption_key
            else:
                messagebox.showerror("Error", "Invalid master password! Exiting the program.")
                exit()
    except Exception as e:
        messagebox.showerror("Error", "An error occurred: " + str(e))
        exit()

# Create the main application window with title and size
window = tk.Tk()
window.withdraw()  # Hide the main window
window.title("Password Vault 07")
window.geometry("1280x720")

# Check the master password before showing the main window
encryption_key = check_master_password()

# Show the main window when the master password is correct
window.deiconify()  

# The class used to generate key, encrypt with salt, and decrypt passwords.
class PasswordManager:
    def __init__(self, key):
        self.key = key
        self.cipher = Fernet(self.key)
    
    # Function to encrypt a password with a salt
    def encrypt_password(self, password, salt=None):
        if salt is None:
            salt = os.urandom(8)
        
        salted_password = salt + password.encode('utf-8')
        encrypted_password = self.cipher.encrypt(salted_password)
        return encrypted_password, salt
    
    # Function to decrypt a password
    def decrypt_password(self, encrypted_password, salt):
        decrypted_password_with_salt = self.cipher.decrypt(encrypted_password)
        plaintext_password = decrypted_password_with_salt[len(salt):].decode('utf-8')
        return plaintext_password


# Function to update the listbox 
def update_listbox():
    # Clear the listbox
    listbox_entries.delete(0, tk.END)

    # Error handling when executing SQL query    
    try:
        # Fetch entries from the database
        cursor.execute("SELECT password_id, service_username, description FROM passwords")
        entries = cursor.fetchall()
        
        # Add entries to the listbox
        for password_id, username, description in entries:
            listbox_entries.insert(tk.END, "ID: " + str(password_id) + " || " + "Username: " + str(username) + " || " + "Description: " + str(description))
    except mysql.connector.Error as err:
        error_label.config(text="Error updating listbox: " + str(err), fg="red")

# Error label to display status
error_label = tk.Label(window, text="", fg="red")
error_label.grid(row=8, column=0, columnspan=2)

# The PasswordVault class is for managing entries in the database.
# It uses the PasswordManager class to encrypt and decrypt passwords.
# It provides methods to add new password entries to the database and fetch all password entries from the database.
class PasswordVault:
    def __init__(self, encryption_key):
        self.password_manager = PasswordManager(encryption_key)

    # Function for adding password entries to the database
    def add_password_entry(self, username, password, description):
        if not username or not password or not description:
            error_label.config(text="Please fill in all fields.")
            return
    
        encrypted_password, salt = self.password_manager.encrypt_password(password)

        # Inserting the result into the database, and adds error handling if not able to store data in the database
        try:
            insert_query = "INSERT INTO passwords (service_username, password_encrypted, description, salt) VALUES (%s, %s, %s, %s)"
            cursor.execute(insert_query, (username, encrypted_password, description, salt))
            db.commit()
            error_label.config(text="Entry added successfully!", fg="green")
            # Update the listbox
            update_listbox()
        except mysql.connector.Error as err:
            error_label.config(text="Error: " + str(err), fg="red")

    def fetch_entries(self):
        fetch_query = "SELECT service_username, description FROM passwords"
        cursor.execute(fetch_query)
        return cursor.fetchall()

# Create a PasswordVault instance
password_vault = PasswordVault(encryption_key)

# Function to get entries and add them with function from password_Vault
def add_entry_from_gui():
    username = entry_username_add.get().strip()
    password = entry_password_add.get().strip()
    description = entry_description.get().strip()
    
    if not username or not password or not description:
        error_label.config(text="Please fill in all fields.")
        return
    
    password_vault.add_password_entry(username, password, description)

    # Clear fields after adding an entry
    entry_username_add.delete(0, tk.END)
    entry_password_add.delete(0, tk.END)
    entry_description.delete(0, tk.END)

# Function for searching in listbox and displaying result
def search_entries():
    # Get the search query from the user
    search_query = simpledialog.askstring("Search Entries", "Enter search query:")
    if search_query:
        # Clear the listbox
        listbox_entries.delete(0, tk.END)

        # Fetch entries from the database matching the search query
        fetch_query = "SELECT password_id, service_username, description FROM passwords WHERE service_username LIKE %s OR description LIKE %s"
        cursor.execute(fetch_query, ('%' + search_query + '%', '%' + search_query + '%'))
        entries = cursor.fetchall()

        # Add matching entries to the listbox
        for password_id, username, description in entries:
            listbox_entries.insert(tk.END, "ID: " + str(password_id) + " || " + "Username: " + str(username) + " || " + "Description: " + str(description))

# Function that clears the search and updates the listbox to show all entries
def clear_search():
    update_listbox()

# Function to retrieve an entry from the listbox
def retrieve_entry():
    # Get the currently selected entry from the listbox
    selected_entry = listbox_entries.curselection()
    if not selected_entry:
        error_label.config(text="No entry selected. Please select an entry to retrieve.", fg="red")
        return

    # Select entry in listbox
    selected_text = listbox_entries.get(selected_entry)

    # Extract the password_id from the selected text
    password_id = selected_text.split(" || ")[0].split(": ")[1]

    # Get the current password from the database
    cursor.execute("SELECT service_username, password_encrypted, salt, description FROM passwords WHERE password_id = %s", (password_id,))
    result = cursor.fetchone()

    if result:
        username, encrypted_password, salt, description = result
        # Ensure the salt is in the correct format for decryption
        if isinstance(salt, bytes):
            byte_salt = salt
        else:
            byte_salt = bytes.fromhex(salt)

        try:
            current_password = password_vault.password_manager.decrypt_password(encrypted_password, byte_salt)

            # Populate the fields with the current details
            entry_username_add.delete(0, tk.END)
            entry_username_add.insert(0, username)
            entry_password_add.delete(0, tk.END)
            entry_password_add.insert(0, current_password)
            entry_description.delete(0, tk.END)
            entry_description.insert(0, description)
        except Exception as e:
            error_label.config(text="Decryption failed: " + str(e), fg="red")
            
    else:
        error_label.config(text="No matching entry found in the database.", fg="red")


# Function to modify entry that is selected, update it and save. Then update listbox again.
def modify_entry():
    # Get the currently selected entry from the listbox
    selected_entry = listbox_entries.curselection()
    if not selected_entry:
        error_label.config(text="No entry selected. Please select an entry to modify.", fg="red")
        return

    # Select entry in listbox
    selected_text = listbox_entries.get(selected_entry)

    # Extract the password_id from the selected text
    password_id = selected_text.split(" || ")[0].split(": ")[1]

    # Get the new details from the fields
    new_username = entry_username_add.get().strip()
    new_password = entry_password_add.get().strip()
    new_description = entry_description.get().strip()

    if new_username and new_password and new_description:
        # Encrypt the new password
        encrypted_password, salt = password_vault.password_manager.encrypt_password(new_password)

        # Update the database
        update_query = "UPDATE passwords SET service_username = %s, password_encrypted = %s, description = %s, salt = %s WHERE password_id = %s"
        cursor.execute(update_query, (new_username, encrypted_password, new_description, salt, password_id))
        db.commit()

        # Update the listbox
        update_listbox()
        error_label.config(text="Entry modified successfully!", fg="green")
    else:
        error_label.config(text="Modification cancelled.", fg="red")


def toggle_password():
    if entry_password_add.cget("show") == "*":
        entry_password_add.config(show="")
    else:
        entry_password_add.config(show="*")

# Function to delete an entry from the listbox
def delete_entry():
    # Get the currently selected entry from the listbox
    selected_entry = listbox_entries.curselection()
    if not selected_entry:
        error_label.config(text="No entry selected. Please select an entry to delete.", fg="red")
        return

    # Select entry in listbox
    selected_text = listbox_entries.get(selected_entry)

    # Extract the password_id from the selected text
    password_id = selected_text.split(" || ")[0].split(": ")[1]

    # Ask for confirmation before deleting
    confirm = messagebox.askyesno("Confirmation", "Are you sure you want to delete the entry with ID: " + str(password_id) + "?")
    if confirm:
        delete_query = "DELETE FROM passwords WHERE password_id = %s"
        cursor.execute(delete_query, (password_id,))
        db.commit()

        # Update the listbox
        update_listbox()
        error_label.config(text="Entry deleted successfully!", fg="green")
    else:
        error_label.config(text="Deletion cancelled.", fg="red")


# Welcome header
welcome_header = tk.Label(window, text="Welcome to Password Vault 07", font=("Arial", 14))
welcome_header.grid(row=0, column=0, columnspan=2)

# Password Vault 07 right text
vault_banner = tk.Label(window, text="Password Vault 07", font=("Arial", 36))
vault_banner.grid(row=0, column=5, columnspan=2)

# Header to add entries
add_entry_label = tk.Label(window, text="Enter username, password and description:", font=("Arial", 12))
add_entry_label.grid(row=1, column=0, columnspan=2)

# Labels and entry widgets for adding username and passwords 
label_username_add = tk.Label(window, text="Username:")
label_username_add.grid(row=2, column=0)

entry_username_add = tk.Entry(window)
entry_username_add.grid(row=2, column=1)

label_password_add = tk.Label(window, text="Password:")
label_password_add.grid(row=3, column=0)

entry_password_add = tk.Entry(window, show="*")
entry_password_add.grid(row=3, column=1)

label_description = tk.Label(window, text="Description:")
label_description.grid(row=4, column=0)

entry_description = tk.Entry(window)
entry_description.grid(row=4, column=1)

# Button to add a new entry
new_login_button = tk.Button(window, text="Add New Entry", command=add_entry_from_gui)
new_login_button.grid(row=5, column=0, padx=5, sticky="w")

# Button to retrieve entries
retrieve_button = tk.Button(window, text="Retrieve Entry", command=retrieve_entry)
retrieve_button.grid(row=5, column=1, padx=5, sticky="w")

# Button to modify an entry
modify_button = tk.Button(window, text="Modify Entry", command=modify_entry)
modify_button.grid(row=5, column=2, padx=5, sticky="w")

# Button to toggle show password on or off
toggle_button = tk.Button(window, text="Toggle Password", command=toggle_password)
toggle_button.grid(row=6, column=0, padx=5, sticky="w")

# Search button
search_button = tk.Button(window, text="Search Entries", command=search_entries)
search_button.grid(row=6, column=1, padx=5, sticky="w")

# Button to clear the search and show all entries again
clear_search_button = tk.Button(window, text="Clear Search", command=clear_search)
clear_search_button.grid(row=6, column=2, padx=5, sticky="w")

# Button to delete entry
delete_button = tk.Button(window, text="Delete Entry", command=delete_entry)
delete_button.grid(row=7, column=0, padx=5, sticky="w")

# Listbox to display added entries
listbox_entries = tk.Listbox(window, width=70, height=30)
listbox_entries.grid(row=0, column=3, rowspan=10, sticky="n", padx=10, pady=10)

# Scrollbar for the Listbox
scrollbar_entries = tk.Scrollbar(window, orient="vertical", command=listbox_entries.yview)
scrollbar_entries.grid(row=0, column=4, rowspan=10, sticky="ns", pady=10)

# Configure the Listbox to use the scrollbar
listbox_entries.config(yscrollcommand=scrollbar_entries.set)

# Call update_listbox to populate the listbox with entries
update_listbox()

# Spacer label
spacer = tk.Label(window, text="")
spacer.grid(row=10, pady=(10, 10))  

# Spacer label
spacer = tk.Label(window, text="")
spacer.grid(row=12, pady=(10, 10))  

# Spacer label
spacer = tk.Label(window, text="")
spacer.grid(row=13, pady=(10, 10))  

# Button to quit the application
button_quit = tk.Button(window, text="Quit", command=exit)
button_quit.grid(row=14, column=0, columnspan=2, padx=10, pady=10)

# Start the Tkinter event loop
window.mainloop()
