- **Constants:**
  - `KEY_SIZE`: 32 bytes (256 bits) for AES-256.
  - `IV_SIZE`: 16 bytes (128 bits) for the initialization vector.

- **Private Methods:**
  - `generateKey()`: Creates a random 256-bit key using OpenSSL's `RAND_bytes`.
  - `saveKey()`: Writes the generated key to a specified file.
  - `loadKey()`: Reads a key from a specified file.
  - `encrypt()`: Performs AES-256-CBC encryption, prepending a random IV to the ciphertext.
  - `decrypt()`: Performs AES-256-CBC decryption, extracting the IV from the ciphertext.
  - `readFile()`: Reads entire file contents into a byte vector.
  - `writeFile()`: Writes byte vector data to a file.
  - `clearInput()`: Clears input buffer (not used in this code, but typically for input cleanup).

---

### Main Functionalities:

#### 1. **Encrypt Message (`encryptMessage`)**
- Prompts user for a message.
- Checks if a key file exists in `C:/encrypted_data/encryption.key`.
  - If yes, loads the key.
  - If no, generates and saves a new key.
- Encrypts the message, saves it as `encrypted_message.txt` in the same folder.
- Reminds user to keep the key safe, as it's needed for decryption.

#### 2. **Encrypt File (`encryptFile`)**
- Asks user for a file path.
- Checks if the file exists and isn't already encrypted.
- Generates a new random key.
- Reads the file's contents.
- Encrypts the data.
- Saves the encrypted data with an appended `.encrypted` extension.
- Saves the key in a `.key` file in the same directory.
- Deletes the original file to keep data hidden.

#### 3. **Decrypt Message (`decryptMessage`)**
- Loads encrypted message and key from default paths or prompts user for custom paths.
- Decrypts the message and displays it.
- Handles errors like wrong key or corrupted data.

#### 4. **Decrypt File (`decryptFile`)**
- Prompts for the encrypted file path.
- Checks for the `.encrypted` extension.
- Attempts to load the corresponding `.key` file automatically or prompts user for key path.
- Reads encrypted data.
- Decrypts and saves the original file (removes `.encrypted` from filename).
- Optionally deletes encrypted file and key after decryption based on user input.

---

### User Interaction:
- The `run()` method displays a menu with options:
  1. Encrypt Message
  2. Decrypt Message
  3. Encrypt File
  4. Decrypt File
  5. Exit
- Loops until user chooses to exit.
