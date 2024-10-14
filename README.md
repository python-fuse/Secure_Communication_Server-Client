# Secure Communication Server-Client

This project implements a secure communication system using RSA and AES encryption. The server uses RSA to securely share an AES session key with the client, which is then used to encrypt messages sent between them. This setup provides a balance between security and performance, utilizing RSA for secure key exchange and AES for fast message encryption.

## Features

- **RSA Key Generation**: The server generates a pair of RSA keys (private and public).
- **AES Session Key Encryption**: The client generates a random AES session key and encrypts it using the server's public RSA key.
- **Secure Message Encryption**: The message is encrypted with AES using the encrypted session key.
- **Message Decryption**: The server decrypts the AES session key using its private RSA key, then decrypts the received message.

## Prerequisites

- Python 3.8+
- `pycryptodome` library for cryptographic functions
- `tkinter` for the GUI

## Installation

1. **Create and start a virtual environment**

   ```
   python -m venv env
   env\Scripts\Activate
   ```

2. **Install Dependencies**

   Make sure you have `pycryptodome` installed. You can install it using:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Server**

   ```bash
   python server.py
   ```

4. **Run the Client**

   ```bash
   python client.py
   ```

## Usage

1. **Start the Server**

   Run the server program to start listening for incoming connections. The server will generate a pair of RSA keys and bind to `localhost` on port `12345`.

2. **Start the Client**

   Run the client program to connect to the server. The client will:

   - Receive the server's public key.
   - Generate a random AES session key.
   - Encrypt the session key using the server's public key.
   - Encrypt the message and send it to the server.

3. **Decryption at the Server**

   The server will:

   - Decrypt the received AES session key using its private key.
   - Decrypt the message using the decrypted AES session key.

## GUI Usage

This project includes a basic GUI built with `tkinter` for both the client and the server.

1. **Starting the Server GUI**

   - Run `python .\gui\server_gui.py` to start the server.
   - Click "Start Server" to begin listening for client connections.

2. **Starting the Client GUI**
   - Run `python .\gui\client_gui.py` to start the client.
   - Click "Connect" to establish a connection with the server.
   - Enter a message and click "Send" to send the encrypted message to the server.

## Encryption Approach

- **RSA (2048-bit)**: Used for encrypting the AES session key to securely share it between the client and server.
- **AES (256-bit in EAX mode)**: Used for encrypting the actual message. EAX mode provides both encryption and authentication, ensuring data integrity.

## Troubleshooting

- **Connection Issues**: Ensure the server is running before starting the client and that both are configured to use the same host and port (`localhost:12345`).
