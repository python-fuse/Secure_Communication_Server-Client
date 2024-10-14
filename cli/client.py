import base64
import socket
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


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 12345))

    # Receive public key from server
    public_key = client_socket.recv(1024)
    print(f"Received public key length: {len(public_key)}")

    # Generate a random session key
    session_key = get_random_bytes(16)
    print(f"Generated session key length: {len(session_key)}")

    # Encrypt the session key with the server's public key
    enc_session_key = encrypt_aes_key(session_key, public_key)
    print(f"Encrypted session key length: {len(enc_session_key)}")

    # Encrypt the message
    message = input("Enter a message: ")
    enc_message = encrypt_message(message, session_key)

    # Send encrypted session key and message
    client_socket.send(enc_session_key)
    client_socket.send(enc_message)

    print(f"Sent encrypted message: {message}")
    print(f"Encrypted message length: {len(enc_message)}")
    print(f"Encrypted message (base64): {base64.b64encode(enc_message).decode()}")

    client_socket.close()


if __name__ == "__main__":
    start_client()
