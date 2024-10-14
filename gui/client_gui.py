"""
This module provides a simple GUI client for connecting to a server, sending encrypted messages, and displaying server responses.

Functions:
    encrypt_aes_key(session_key, public_key):
        Encrypts the AES session key using the server's public RSA key.

    encrypt_message(message, session_key):
        Encrypts a message using the AES session key.

    start_client_gui():
        Initializes and starts the client GUI application.

    start_client():
        Establishes a connection to the server, receives the server's public key, generates a session key, and sends the encrypted session key to the server.

    send_message():
        Encrypts and sends a message to the server.

    stop_client():
        Closes the connection to the server and stops the GUI application.

    display_message(msg):
        Displays a message in the GUI message box.

    run_client_in_thread():
        Runs the client connection in a separate thread.

GUI Elements:
    root:
        The main window of the GUI application.

    start_button:
        Button to connect to the server.

    message_entry:
        Entry widget for typing messages to send to the server.

    send_button:
        Button to send the typed message to the server.

    message_box:
        Text widget to display messages and server responses.

    stop_button:
        Button to disconnect from the server and close the application.
"""

import base64
import socket
import threading
from tkinter import Tk, Button, Entry, Text, END
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


def encrypt_aes_key(session_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(session_key)


def encrypt_message(message, session_key):
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    return cipher_aes.nonce + ciphertext + tag


def start_client_gui():
    client_socket = None
    session_key = None
    public_key = None

    def start_client():
        nonlocal client_socket, session_key, public_key
        try:
            # Set up connection
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(("localhost", 12345))

            display_message("Connected to the server.")

            # Receive public key from server
            public_key = client_socket.recv(1024)
            display_message(f"Received public key length: {len(public_key)}")

            # Generate a random session key
            session_key = get_random_bytes(16)
            display_message(f"Generated session key length: {len(session_key)}")

            # Encrypt the session key with the server's public key
            enc_session_key = encrypt_aes_key(session_key, public_key)
            client_socket.send(enc_session_key)
            display_message("Sent encrypted session key.")
        except Exception as e:
            display_message(f"Client error: {e}")
            if client_socket:
                client_socket.close()

    def send_message():
        nonlocal session_key
        try:
            message = message_entry.get()
            if not message:
                display_message("Please enter a message.")
                return

            # Encrypt the message
            enc_message = encrypt_message(message, session_key)

            # Send the length of the encrypted message
            message_length = len(enc_message)
            client_socket.send(message_length.to_bytes(4, byteorder="big"))

            # Send the encrypted message
            client_socket.send(enc_message)
            display_message(f"Sent encrypted message: {enc_message}")
            message_entry.delete(0, END)
        except Exception as e:
            display_message(f"Send error: {e}")

    def stop_client():
        if client_socket:
            client_socket.close()
            display_message("Disconnected from the server.")
        root.destroy()

    def display_message(msg):
        message_box.insert(END, msg + "\n")
        message_box.see(END)

    def run_client_in_thread():
        threading.Thread(target=start_client, daemon=True).start()

    # GUI setup
    root = Tk()
    root.title("Client")
    root.geometry("500x500")

    start_button = Button(root, text="Connect to Server", command=run_client_in_thread)
    start_button.pack()

    message_entry = Entry(root, width=50)
    message_entry.pack()

    send_button = Button(root, text="Send Message", command=send_message)
    send_button.pack()

    message_box = Text(root, height=20, width=500)
    message_box.pack()

    stop_button = Button(root, text="Disconnect", command=stop_client)
    stop_button.pack()

    root.mainloop()


if __name__ == "__main__":
    start_client_gui()
