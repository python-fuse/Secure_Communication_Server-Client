import socket
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes

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


def generate_rsa_keys() -> tuple[bytes, bytes]:
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def decrypt_aes_key(enc_session_key, private_key) -> bytes:
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(enc_session_key)


def decrypt_message(enc_message, session_key) -> str:
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=enc_message[:16])
    data = cipher_aes.decrypt_and_verify(enc_message[16:-16], enc_message[-16:])
    return data.decode()


def start_server() -> None:
    private_key, public_key = generate_rsa_keys()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 12345))
    server_socket.listen(1)

    print("Server is listening...")

    conn, address = server_socket.accept()
    print(f"Connection from {address}")

    conn.send(public_key)

    enc_session_key = conn.recv(256)
    enc_message = conn.recv(1024)

    session_key = decrypt_aes_key(enc_session_key, private_key)
    message = decrypt_message(enc_message, session_key)

    print(f"Decrypted message: {message}")
    conn.close()


if __name__ == "__main__":
    start_server()
