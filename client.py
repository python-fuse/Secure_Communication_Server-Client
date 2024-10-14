import socket
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes


def encrypt_aes_key(session_key, public_key) -> bytes:
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(session_key)


def encrypt_message(message, session_key) -> bytes:
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    return cipher_aes.nonce + ciphertext + tag


def start_client() -> None:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 12345))

    public_key = client_socket.recv(1024)

    session_key = get_random_bytes(16)
    enc_session_key = encrypt_aes_key(session_key, public_key)
    client_socket.send(enc_session_key)

    message = input("Enter a message: ")
    enc_message = encrypt_message(message, session_key)

    client_socket.send(enc_session_key)
    client_socket.send(enc_message)

    print(f"Sent message: {message}")

    client_socket.close()


if __name__ == "__main__":
    start_client()
