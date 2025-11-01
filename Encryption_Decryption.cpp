#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

namespace fs = std::filesystem;

class EncryptionTool {
private:
    static const int KEY_SIZE = 32;  // 256 bits for AES-256
    static const int IV_SIZE = 16;   // 128 bits for AES IV

    // Generate random key
    std::vector<unsigned char> generateKey() {
        std::vector<unsigned char> key(KEY_SIZE);
        if (RAND_bytes(key.data(), KEY_SIZE) != 1) {
            throw std::runtime_error("Failed to generate random key");
        }
        return key;
    }

    // Save key to file
    void saveKey(const std::vector<unsigned char>& key, const std::string& keyPath) {
        std::ofstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Failed to create key file");
        }
        keyFile.write(reinterpret_cast<const char*>(key.data()), key.size());
        keyFile.close();
        std::cout << "[+] Key generated and saved to: " << keyPath << std::endl;
    }

    // Load key from file
    std::vector<unsigned char> loadKey(const std::string& keyPath) {
        std::ifstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Key file not found");
        }

        std::vector<unsigned char> key(KEY_SIZE);
        keyFile.read(reinterpret_cast<char*>(key.data()), KEY_SIZE);
        keyFile.close();
        return key;
    }

    // AES-256-CBC encryption
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,
                                      const std::vector<unsigned char>& key) {
        std::vector<unsigned char> iv(IV_SIZE);
        RAND_bytes(iv.data(), IV_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }

        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len = 0, ciphertext_len = 0;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed");
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption finalization failed");
        }
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        // Prepend IV to ciphertext
        std::vector<unsigned char> result(iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

        return result;
    }

    // AES-256-CBC decryption
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext,
                                      const std::vector<unsigned char>& key) {
        if (ciphertext.size() < IV_SIZE) {
            throw std::runtime_error("Invalid ciphertext");
        }

        std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + IV_SIZE);
        std::vector<unsigned char> actual_ciphertext(ciphertext.begin() + IV_SIZE, ciphertext.end());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }

        std::vector<unsigned char> plaintext(actual_ciphertext.size());
        int len = 0, plaintext_len = 0;

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, actual_ciphertext.data(), actual_ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed");
        }
        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed - wrong key or corrupted file");
        }
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        plaintext.resize(plaintext_len);
        return plaintext;
    }

    // Read file into vector
    std::vector<unsigned char> readFile(const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + path);
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<unsigned char> buffer(size);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            throw std::runtime_error("Failed to read file");
        }
        return buffer;
    }

    // Write vector to file
    void writeFile(const std::string& path, const std::vector<unsigned char>& data) {
        std::ofstream file(path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot create file: " + path);
        }
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    // Clear input buffer
    void clearInput() {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

public:
    void encryptMessage() {
        std::cout << "\n=== ENCRYPT MESSAGE ===" << std::endl;
        std::cout << "Enter the message to encrypt: ";

        std::string message;
        std::getline(std::cin, message);

        if (message.empty()) {
            std::cout << "[-] No message provided!" << std::endl;
            return;
        }

        try {
            fs::path encryptedFolder = "C:/encrypted_data";
            fs::create_directories(encryptedFolder);

            fs::path keyPath = encryptedFolder / "encryption.key";
            fs::path outputPath = encryptedFolder / "encrypted_message.txt";

            std::vector<unsigned char> key;
            if (fs::exists(keyPath)) {
                std::cout << "[*] Loading existing key..." << std::endl;
                key = loadKey(keyPath.string());
            } else {
                std::cout << "[*] Generating new key..." << std::endl;
                key = generateKey();
                saveKey(key, keyPath.string());
            }

            std::vector<unsigned char> plaintext(message.begin(), message.end());
            std::vector<unsigned char> ciphertext = encrypt(plaintext, key);

            writeFile(outputPath.string(), ciphertext);

            std::cout << "[+] Message encrypted successfully!" << std::endl;
            std::cout << "[+] Encrypted file saved to: " << outputPath << std::endl;
            std::cout << "[+] Key file location: " << keyPath << std::endl;
            std::cout << "\n[!] IMPORTANT: Keep your key file safe! You need it to decrypt." << std::endl;

        } catch (const std::exception& e) {
            std::cout << "[-] Error: " << e.what() << std::endl;
        }
    }

    void encryptFile() {
        std::cout << "\n=== ENCRYPT FILE ===" << std::endl;
        std::cout << "Enter the full path to the file you want to encrypt: ";

        std::string filePath;
        std::getline(std::cin, filePath);

        // Remove quotes if present
        filePath.erase(std::remove(filePath.begin(), filePath.end(), '\"'), filePath.end());

        try {
            fs::path file(filePath);

            if (!fs::exists(file)) {
                std::cout << "[-] File not found: " << file << std::endl;
                return;
            }

            if (!fs::is_regular_file(file)) {
                std::cout << "[-] Path is not a file" << std::endl;
                return;
            }

            if (file.extension() == ".encrypted") {
                std::cout << "[-] File appears to be already encrypted!" << std::endl;
                return;
            }

            std::vector<unsigned char> key = generateKey();
            fs::path keyPath = file.parent_path() / (file.stem().string() + ".key");

            std::cout << "[*] Reading file: " << file << std::endl;
            std::vector<unsigned char> fileData = readFile(file.string());
            double fileSize = fileData.size() / 1024.0;
            std::cout << "[*] File size: " << fileSize << " KB" << std::endl;

            std::cout << "[*] Encrypting file..." << std::endl;
            std::vector<unsigned char> encryptedData = encrypt(fileData, key);

            fs::path encryptedPath = file.parent_path() / (file.stem().string() + file.extension().string() + ".encrypted");
            writeFile(encryptedPath.string(), encryptedData);

            saveKey(key, keyPath.string());

            fs::remove(file);

            std::cout << "[+] File encrypted successfully!" << std::endl;
            std::cout << "[+] Encrypted file: " << encryptedPath << std::endl;
            std::cout << "[+] Key file saved to: " << keyPath << std::endl;
            std::cout << "\n[!] IMPORTANT: Keep the .key file with the encrypted file!" << std::endl;
            std::cout << "[!] Both files are in: " << file.parent_path() << std::endl;

        } catch (const std::exception& e) {
            std::cout << "[-] Encryption failed: " << e.what() << std::endl;
        }
    }

    void decryptMessage() {
        std::cout << "\n=== DECRYPT MESSAGE ===" << std::endl;

        fs::path encryptedFolder = "C:/encrypted_data";
        fs::path defaultKey = encryptedFolder / "encryption.key";
        fs::path defaultEncrypted = encryptedFolder / "encrypted_message.txt";

        std::cout << "Enter the path to encrypted file (or press Enter for default): ";
        std::string filePathStr;
        std::getline(std::cin, filePathStr);
        fs::path filePath = filePathStr.empty() ? defaultEncrypted : fs::path(filePathStr);

        std::cout << "Enter the path to key file (or press Enter for default): ";
        std::string keyPathStr;
        std::getline(std::cin, keyPathStr);
        fs::path keyPath = keyPathStr.empty() ? defaultKey : fs::path(keyPathStr);

        try {
            if (!fs::exists(filePath)) {
                std::cout << "[-] Encrypted file not found: " << filePath << std::endl;
                return;
            }

            if (!fs::exists(keyPath)) {
                std::cout << "[-] Key file not found: " << keyPath << std::endl;
                return;
            }

            std::vector<unsigned char> key = loadKey(keyPath.string());
            std::vector<unsigned char> ciphertext = readFile(filePath.string());
            std::vector<unsigned char> plaintext = decrypt(ciphertext, key);
            std::string message(plaintext.begin(), plaintext.end());

            std::cout << "\n[+] Message decrypted successfully!" << std::endl;
            std::cout << "[+] Decrypted message:\n" << std::endl;
            std::cout << std::string(50, '-') << std::endl;
            std::cout << message << std::endl;
            std::cout << std::string(50, '-') << std::endl;

        } catch (const std::exception& e) {
            std::cout << "[-] Decryption failed: " << e.what() << std::endl;
            std::cout << "[!] This could mean:" << std::endl;
            std::cout << "    - Wrong key file" << std::endl;
            std::cout << "    - Corrupted encrypted file" << std::endl;
            std::cout << "    - File was not encrypted with this key" << std::endl;
        }
    }

    void decryptFile() {
        std::cout << "\n=== DECRYPT FILE ===" << std::endl;
        std::cout << "Enter the path to encrypted file: ";

        std::string filePathStr;
        std::getline(std::cin, filePathStr);
        filePathStr.erase(std::remove(filePathStr.begin(), filePathStr.end(), '\"'), filePathStr.end());

        try {
            fs::path filePath(filePathStr);

            if (!fs::exists(filePath)) {
                std::cout << "[-] Encrypted file not found: " << filePath << std::endl;
                return;
            }

            if (filePath.extension() != ".encrypted") {
                std::cout << "[?] File doesn't have .encrypted extension. Continue anyway? (yes/no): ";
                std::string confirm;
                std::getline(std::cin, confirm);
                if (confirm != "yes" && confirm != "y") {
                    return;
                }
            }

            std::string baseName = filePath.stem().string();
            if (baseName.size() > 10 && baseName.substr(baseName.size() - 10) == ".encrypted") {
                baseName = baseName.substr(0, baseName.size() - 10);
            }

            size_t dotPos = baseName.find('.');
            if (dotPos != std::string::npos) {
                baseName = baseName.substr(0, dotPos);
            }

            fs::path defaultKeyPath = filePath.parent_path() / (baseName + ".key");

            fs::path keyPath;
            if (fs::exists(defaultKeyPath)) {
                std::cout << "[*] Found key file: " << defaultKeyPath << std::endl;
                std::cout << "[?] Use this key file? (yes/no): ";
                std::string answer;
                std::getline(std::cin, answer);

                if (answer == "yes" || answer == "y" || answer.empty()) {
                    keyPath = defaultKeyPath;
                } else {
                    std::cout << "Enter the path to key file: ";
                    std::string keyStr;
                    std::getline(std::cin, keyStr);
                    keyPath = fs::path(keyStr);
                }
            } else {
                std::cout << "Enter the path to key file (default would be: " << defaultKeyPath << "): ";
                std::string keyStr;
                std::getline(std::cin, keyStr);
                if (keyStr.empty()) {
                    std::cout << "[-] Key file not found: " << defaultKeyPath << std::endl;
                    return;
                }
                keyPath = fs::path(keyStr.erase(std::remove(keyStr.begin(), keyStr.end(), '\"'), keyStr.end()));
            }

            if (!fs::exists(keyPath)) {
                std::cout << "[-] Key file not found: " << keyPath << std::endl;
                return;
            }

            std::cout << "[*] Reading encrypted file..." << std::endl;
            std::vector<unsigned char> key = loadKey(keyPath.string());
            std::vector<unsigned char> ciphertext = readFile(filePath.string());

            std::cout << "[*] Decrypting file..." << std::endl;
            std::vector<unsigned char> plaintext = decrypt(ciphertext, key);

            std::string originalName = filePath.filename().string();
            if (originalName.size() > 10 && originalName.substr(originalName.size() - 10) == ".encrypted") {
                originalName = originalName.substr(0, originalName.size() - 10);
            } else {
                originalName = "decrypted_" + originalName;
            }

            fs::path decryptedPath = filePath.parent_path() / originalName;
            writeFile(decryptedPath.string(), plaintext);

            double fileSize = plaintext.size() / 1024.0;
            std::cout << "\n[+] File decrypted successfully!" << std::endl;
            std::cout << "[+] Decrypted file saved to: " << decryptedPath << std::endl;
            std::cout << "[+] File size: " << fileSize << " KB" << std::endl;

            std::cout << "\n[?] Delete the encrypted file and key? (yes/no): ";
            std::string deleteAnswer;
            std::getline(std::cin, deleteAnswer);

            if (deleteAnswer == "yes" || deleteAnswer == "y") {
                fs::remove(filePath);
                std::cout << "[+] Encrypted file deleted: " << filePath << std::endl;
                if (fs::exists(keyPath)) {
                    fs::remove(keyPath);
                    std::cout << "[+] Key file deleted: " << keyPath << std::endl;
                }
            } else {
                std::cout << "[*] Encrypted file kept: " << filePath << std::endl;
                std::cout << "[*] Key file kept: " << keyPath << std::endl;
            }

        } catch (const std::exception& e) {
            std::cout << "[-] Decryption failed: " << e.what() << std::endl;
            std::cout << "[!] This could mean:" << std::endl;
            std::cout << "    - Wrong key file" << std::endl;
            std::cout << "    - Corrupted encrypted file" << std::endl;
            std::cout << "    - File was not encrypted with this key" << std::endl;
        }
    }

    void run() {
        std::cout << std::string(50, '=') << std::endl;
        std::cout << "     DENIABLE ENCRYPTION SYSTEM (C++)" << std::endl;
        std::cout << std::string(50, '=') << std::endl;

        while (true) {
            std::cout << "\n=== MAIN MENU ===" << std::endl;
            std::cout << "1. Encrypt Message" << std::endl;
            std::cout << "2. Decrypt Message" << std::endl;
            std::cout << "3. Encrypt File (PDF, images, documents, etc.)" << std::endl;
            std::cout << "4. Decrypt File" << std::endl;
            std::cout << "5. Exit" << std::endl;

            std::cout << "\nSelect an option (1-5): ";
            std::string choice;
            std::getline(std::cin, choice);

            if (choice == "1") {
                encryptMessage();
            } else if (choice == "2") {
                decryptMessage();
            } else if (choice == "3") {
                encryptFile();
            } else if (choice == "4") {
                decryptFile();
            } else if (choice == "5") {
                std::cout << "\n[*] Exiting... Stay secure!" << std::endl;
                break;
            } else {
                std::cout << "[-] Invalid option. Please select 1-5." << std::endl;
            }
        }
    }
};

int main() {
    EncryptionTool tool;
    tool.run();
    return 0;
}