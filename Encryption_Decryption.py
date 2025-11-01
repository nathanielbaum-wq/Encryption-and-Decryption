import os
import shutil
from cryptography.fernet import Fernet
from pathlib import Path


def generate_key(key_path):
    """Generate and save an encryption key."""
    key = Fernet.generate_key()
    with open(key_path, 'wb') as key_file:
        key_file.write(key)
    print(f"[+] Key generated and saved to: {key_path}")
    return key


def load_key(key_path):
    """Load the encryption key from file."""
    try:
        with open(key_path, 'rb') as key_file:
            return key_file.read()
    except FileNotFoundError:
        print(f"[-] Key file not found at: {key_path}")
        return None


def encrypt_message():
    """Encrypt a message and save to C drive."""
    print("\n=== ENCRYPT MESSAGE ===")
    message = input("Enter the message to encrypt: ")

    if not message:
        print("[-] No message provided!")
        return

    c_drive = Path("C:/")
    encrypted_folder = c_drive / "encrypted_data"
    encrypted_folder.mkdir(exist_ok=True)

    key_path = encrypted_folder / "encryption.key"
    output_path = encrypted_folder / "encrypted_message.txt"

    if not key_path.exists():
        print("[*] No key found. Generating new key...")
        key = generate_key(key_path)
    else:
        print("[*] Loading existing key...")
        key = load_key(key_path)

    if not key:
        return

    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())

    with open(output_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_message)

    print(f"[+] Message encrypted successfully!")
    print(f"[+] Encrypted file saved to: {output_path}")
    print(f"[+] Key file location: {key_path}")
    print(f"\n[!] IMPORTANT: Keep your key file safe! You need it to decrypt.")


def encrypt_file():
    """Encrypt any file (PDF, images, documents, etc.) in-place."""
    print("\n=== ENCRYPT FILE ===")
    file_path_input = input("Enter the full path to the file you want to encrypt (e.g., C:/Documents/file.pdf): ").strip()
    file_path_input = file_path_input.strip('"')
    file_path = Path(file_path_input)

    if not file_path.exists():
        print(f"[-] File not found: {file_path}")
        return

    if not file_path.is_file():
        print(f"[-] Path is not a file: {file_path}")
        return

    if file_path.suffix == ".encrypted":
        print(f"[-] File appears to be already encrypted!")
        return

    try:
        print(f"[*] Reading file: {file_path}")
        with open(file_path, 'rb') as file:
            file_data = file.read()

        file_size = len(file_data) / 1024  # KB
        print(f"[*] File size: {file_size:.2f} KB")
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return

    try:
        print(f"[*] Encrypting file...")
        fernet = Fernet(Fernet.generate_key())
        encrypted_data = fernet.encrypt(file_data)

        original_extension = file_path.suffix
        encrypted_filename = f"{file_path.stem}{original_extension}.encrypted"
        encrypted_path = file_path.parent / encrypted_filename

        with open(encrypted_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        # Save the key file in same directory
        key_filename = f"{file_path.stem}.key"
        key_path = file_path.parent / key_filename
        with open(key_path, 'wb') as key_file:
            key_file.write(fernet._signing_key + fernet._encryption_key)

        # Delete the original unencrypted file
        file_path.unlink()

        print(f"[+] File encrypted successfully!")
        print(f"[+] Encrypted file: {encrypted_path}")
        print(f"[+] Key file saved to: {key_path}")
        print(f"\n[!] IMPORTANT: Keep the .key file with the encrypted file!")
        print(f"[!] Both files are in: {file_path.parent}")
    except Exception as e:
        print(f"[-] Encryption failed: {e}")


def decrypt_file():
    """Decrypt an encrypted file in-place."""
    print("\n=== DECRYPT FILE ===")
    file_path_input = input("Enter the path to encrypted file: ").strip()
    file_path_input = file_path_input.strip('"')
    file_path = Path(file_path_input)

    if not file_path.exists():
        print(f"[-] Encrypted file not found: {file_path}")
        return

    if not file_path.suffix == ".encrypted":
        confirm = input("[?] File doesn't have .encrypted extension. Continue anyway? (yes/no): ").strip().lower()
        if confirm not in ['yes', 'y']:
            return

    # Determine base name for key lookup
    if file_path.name.endswith(".encrypted"):
        base_name = file_path.name[:-10]  # Remove ".encrypted"
        base_stem = base_name.split('.')[0]
    else:
        base_stem = file_path.stem

    key_filename = f"{base_stem}.key"
    default_key_path = file_path.parent / key_filename

    # Ask user for key file location
    if default_key_path.exists():
        print(f"[*] Found key file: {default_key_path}")
        use_default = input("[?] Use this key file? (yes/no): ").strip().lower()
        if use_default in ['yes', 'y', '']:
            key_path = default_key_path
        else:
            key_path_input = input("Enter the path to key file: ").strip()
            key_path = Path(key_path_input.strip('"'))
    else:
        key_path_input = input(f"Enter the path to key file (default would be: {default_key_path}): ").strip()
        if not key_path_input:
            print(f"[-] Key file not found: {default_key_path}")
            return
        key_path = Path(key_path_input.strip('"'))

    if not key_path.exists():
        print(f"[-] Key file not found: {key_path}")
        return

    # Load key
    key = load_key(key_path)
    if not key:
        return

    # Read encrypted file
    try:
        print(f"[*] Reading encrypted file...")
        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
    except Exception as e:
        print(f"[-] Error reading encrypted file: {e}")
        return

    # Decrypt the file
    try:
        print(f"[*] Decrypting file...")
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)

        # Determine original filename
        if file_path.name.endswith(".encrypted"):
            original_name = file_path.name[:-10]
        else:
            original_name = f"decrypted_{file_path.name}"

        # Save to same directory
        decrypted_path = file_path.parent / original_name

        # Save decrypted file
        with open(decrypted_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        file_size = len(decrypted_data) / 1024  # KB
        print(f"\n[+] File decrypted successfully!")
        print(f"[+] Decrypted file saved to: {decrypted_path}")
        print(f"[+] File size: {file_size:.2f} KB")

        # Ask if user wants to delete encrypted file and key
        delete_encrypted = input("\n[?] Delete the encrypted file and key? (yes/no): ").strip().lower()
        if delete_encrypted in ['yes', 'y']:
            file_path.unlink()
            print(f"[+] Encrypted file deleted: {file_path}")
            if key_path.exists():
                key_path.unlink()
                print(f"[+] Key file deleted: {key_path}")
        else:
            print(f"[*] Encrypted file kept: {file_path}")
            print(f"[*] Key file kept: {key_path}")

    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        print("[!] This could mean:")
        print("    - Wrong key file")
        print("    - Corrupted encrypted file")
        print("    - File was not encrypted with this key")


def decrypt_message():
    """Decrypt a message from file."""
    print("\n=== DECRYPT MESSAGE ===")
    c_drive = Path("C:/")
    encrypted_folder = c_drive / "encrypted_data"
    default_key = encrypted_folder / "encryption.key"
    default_encrypted = encrypted_folder / "encrypted_message.txt"

    file_path_input = input(f"Enter the path to encrypted file (or press Enter for default: {default_encrypted}): ").strip()
    if not file_path_input:
        file_path = default_encrypted
    else:
        file_path = Path(file_path_input)

    key_path_input = input(f"Enter the path to key file (or press Enter for default: {default_key}): ").strip()
    if not key_path_input:
        key_path = default_key
    else:
        key_path = Path(key_path_input)

    if not file_path.exists():
        print(f"[-] Encrypted file not found: {file_path}")
        return

    if not key_path.exists():
        print(f"[-] Key file not found: {key_path}")
        return

    key = load_key(key_path)
    if not key:
        return

    try:
        with open(file_path, 'rb') as encrypted_file:
            encrypted_message = encrypted_file.read()
    except Exception as e:
        print(f"[-] Error reading encrypted file: {e}")
        return

    try:
        fernet = Fernet(key)
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        print(f"\n[+] Message decrypted successfully!")
        print(f"[+] Decrypted message:\n")
        print("-" * 50)
        print(decrypted_message)
        print("-" * 50)
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        print("[!] This could mean:")
        print("    - Wrong key file")
        print("    - Corrupted encrypted file")
        print("    - File was not encrypted with this key")


def main():
    """Main menu loop."""
    print("=" * 50)
    print("     DENIABLE ENCRYPTION SYSTEM")
    print("=" * 50)

    while True:
        print("\n=== MAIN MENU ===")
        print("1. Encrypt Message")
        print("2. Decrypt Message")
        print("3. Encrypt File (PDF, images, documents, etc.)")
        print("4. Decrypt File")
        print("5. Exit")

        choice = input("\nSelect an option (1-5): ").strip()

        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            encrypt_file()
        elif choice == "4":
            decrypt_file()
        elif choice == "5":
            print("\n[*] Exiting... Stay secure!")
            break
        else:
            print("[-] Invalid option. Please select 1-5.")


if __name__ == '__main__':
    main()