# Password Manager

This is a simple command-line password manager written in C. It uses OpenSSL for encryption and decryption of passwords, providing a basic level of security for storing sensitive information. The program allows users to add, retrieve, and store website credentials in an encrypted format.

## Features

- Add website credentials (website, username, password).
- Retrieve and display credentials based on the website name.
- Store credentials in an encrypted format using AES-128 CBC mode.
- Use a master password to encrypt/decrypt credentials.

## Dependencies

- OpenSSL: This project uses OpenSSL for encryption and decryption. Ensure you have OpenSSL installed on your system.

## Compilation

To compile the password manager, you need to link against the OpenSSL libraries. Here is an example of how you might compile the program:

gcc password_manager.c -o password_manager -lcrypto