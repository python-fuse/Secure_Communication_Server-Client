"""
This module implements a simple server GUI that uses RSA and AES encryption for secure communication.

Functions:
    generate_rsa_keys() -> Tuple[bytes, bytes]:
        Generates a pair of RSA keys (private and public).

    decrypt_aes_key(enc_session_key: bytes, private_key: bytes) -> bytes:
        Decrypts an AES session key using the provided RSA private key.

    decrypt_message(enc_message: bytes, session_key: bytes) -> Optional[str]:
        Decrypts an encrypted message using the provided AES session key.

    start_server_gui():
        Initializes and starts the server GUI, which includes starting the server,
        handling client connections, and decrypting received messages.

    start_server():
        Starts the server, generates RSA keys, handles client connections,
        and decrypts received messages.

    stop_server():
        Stops the server and closes the GUI.

    display_message(msg: str):
        Displays a message in the GUI message box.

    run_server_in_thread():
        Runs the server in a separate thread to keep the GUI responsive.
"""

import base64
import socket
import threading
from tkinter import Tk, Button, Text, END
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def decrypt_aes_key(enc_session_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(enc_session_key)


def decrypt_message(enc_message, session_key):
    try:
        nonce = enc_message[:16]
        ciphertext = enc_message[16:-16]
        tag = enc_message[-16:]
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data.decode()
    except ValueError as e:
        print(f"Decryption error: {e}")
        return None


def start_server_gui():
    server_socket = None
    private_key = None
    session_key = None

    def start_server():
        nonlocal server_socket, private_key, session_key
        try:
            private_key, public_key = generate_rsa_keys()

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(("localhost", 12345))
            server_socket.listen(1)

            display_message("Server is listening...")

            conn, addr = server_socket.accept()
            display_message(f"Connection from: {addr}")

            # Send public key to client
            conn.send(public_key)

            # Receive encrypted session key
            enc_session_key = conn.recv(256)
            session_key = decrypt_aes_key(enc_session_key, private_key)

            display_message("Session key decrypted successfully.")

            # Start listening for messages
            while True:
                # Receive message length
                message_length_bytes = conn.recv(4)
                if not message_length_bytes:
                    break
                message_length = int.from_bytes(message_length_bytes, byteorder="big")

                # Receive the encrypted message
                enc_message = b""
                while len(enc_message) < message_length:
                    packet = conn.recv(message_length - len(enc_message))
                    if not packet:
                        break
                    enc_message += packet

                if len(enc_message) == message_length:
                    # Decrypt the message
                    message = decrypt_message(enc_message, session_key)
                    if message:
                        display_message(f"Decrypted message: {message}")
                    else:
                        display_message("Failed to decrypt the message.")
                else:
                    display_message("Message reception error.")

        except Exception as e:
            display_message(f"Server error: {e}")
        finally:
            if server_socket:
                server_socket.close()

    def stop_server():
        if server_socket:
            server_socket.close()
            display_message("Server stopped.")
        root.destroy()

    def display_message(msg):
        message_box.insert(END, msg + "\n")
        message_box.see(END)

    def run_server_in_thread():
        threading.Thread(target=start_server, daemon=True).start()

    # GUI setup
    root = Tk()
    root.title("Server")

    start_button = Button(root, text="Start Server", command=run_server_in_thread)
    start_button.pack()

    message_box = Text(root, height=20, width=50)
    message_box.pack()

    stop_button = Button(root, text="Stop Server", command=stop_server)
    stop_button.pack()

    root.mainloop()


if __name__ == "__main__":
    start_server_gui()
