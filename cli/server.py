import base64
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

"""
This module implements a simple server that uses RSA and AES encryption to securely receive and decrypt messages.

Functions:
    generate_rsa_keys() -> Tuple[bytes, bytes]:
        Generates a pair of RSA keys (private and public).

    decrypt_aes_key(enc_session_key: bytes, private_key: bytes) -> bytes:
        Decrypts an AES session key using the provided RSA private key.

    decrypt_message(enc_message: bytes, session_key: bytes) -> str:
        Decrypts an encrypted message using the provided AES session key.

    start_server() -> None:
        Starts the server, listens for incoming connections, and handles the decryption of received messages.
"""


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
        print(f"Encrypted message length: {len(enc_message)}")
        print(f"Nonce: {base64.b64encode(nonce).decode()}")
        print(f"Ciphertext: {base64.b64encode(ciphertext).decode()}")
        print(f"Tag: {base64.b64encode(tag).decode()}")
        return None


def start_server():
    private_key, public_key = generate_rsa_keys()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 12345))
    server_socket.listen(1)

    print("Server is listening...")

    conn, addr = server_socket.accept()
    print(f"Connection from: {addr}")

    # Send public key to client
    conn.send(public_key)

    # Receive encrypted session key and message
    enc_session_key = conn.recv(256)
    enc_message = conn.recv(1024)

    print(f"Received encrypted session key length: {len(enc_session_key)}")
    print(f"Received encrypted message length: {len(enc_message)}")

    # Decrypt session key and message
    session_key = decrypt_aes_key(enc_session_key, private_key)
    print(f"Decrypted session key length: {len(session_key)}")

    message = decrypt_message(enc_message, session_key)

    if message:
        print(f"Decrypted message: {message}")
    else:
        print("Failed to decrypt the message.")

    conn.close()


if __name__ == "__main__":
    start_server()
