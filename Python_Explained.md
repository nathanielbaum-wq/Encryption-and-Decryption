This Python script implements a simple, menu-driven encryption and decryption system for messages and files using the `cryptography` library's Fernet symmetric encryption. Here's an overview of what it does:

### Main Features:
- **Encrypt a message** entered by the user and save it to a file on the C: drive.
- **Decrypt a message** from a saved encrypted file.
- **Encrypt any file** (like PDFs, images, documents) in-place, saving the encrypted version and a key file.
- **Decrypt an encrypted file** using the corresponding key, with options to delete the original encrypted and key files after decryption.
- Maintains a basic menu interface for user interaction.

### Breakdown of Core Functions:

1. **Key Generation & Loading**
   - `generate_key(key_path)`: Creates a new encryption key and saves it to the specified path.
   - `load_key(key_path)`: Loads an existing key from a file.

2. **Encrypt a Message (`encrypt_message`)**
   - Prompts the user for a message.
   - Checks if an encryption key exists in `C:/encrypted_data/encryption.key`; if not, generates one.
   - Encrypts the message and saves it as `encrypted_message.txt` in `C:/encrypted_data/`.
   - Reminds the user to keep the key safe for decryption.

3. **Encrypt a File (`encrypt_file`)**
   - Asks for a file path.
   - Reads the file, encrypts its contents with a new key, and saves:
     - The encrypted file with `.encrypted` extension.
     - The key in a `.key` file in the same directory.
   - Deletes the original unencrypted file to keep the data "hidden."

4. **Decrypt a File (`decrypt_file`)**
   - Asks for the encrypted file path.
   - Looks for the corresponding `.key` file or prompts for its location.
   - Decrypts the file and saves it with the original filename.
   - Optionally deletes the encrypted file and key after successful decryption.

5. **Decrypt a Message (`decrypt_message`)**
   - Reads an encrypted message and key from default location or user-specified paths.
   - Decrypts and displays the original message.

6. **Main Menu (`main`)**
   - Provides options to encrypt/decrypt messages and files.
   - Loops until the user exits.

### Security notes:
- Each file encryption generates a unique key stored separately.
- The script emphasizes keeping your key files safe, as they are essential for decryption.
- This is a basic implementation; for serious security, consider additional protections and error handling.

---

Would you like me to help you improve, customize, or explain any specific part of this code?
