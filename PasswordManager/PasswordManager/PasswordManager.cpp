#include <iostream>
#include <vector>
#include <string>
#include <limits>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <conio.h>   // for masked password input (_getch) - Windows only
#include <sodium.h>

// ---------- File / folder paths ----------
const std::string DATA_FOLDER = "data";
const std::string DATA_FILE = "data/vault.dat"; // binary encrypted file now, not plain text

// ---------- Data model ----------
struct PasswordEntry {
    std::string site;
    std::string username;
    std::string password;
};

// ---------- Masked password input ----------
// Reads a password from the console, printing '*' instead of the real characters.
std::string promptPassword(const std::string& prompt) {
    std::cout << prompt;
    std::string password;
    char ch;
    while ((ch = _getch()) != '\r') { // Enter key
        if (ch == '\b') { // Backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // erase the last '*' visually
            }
        }
        else {
            password.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << "\n";
    return password;
}

// ---------- Serialization ----------
// Combines all entries into a single string, 3 lines per entry (site/username/password)
std::string serializeEntries(const std::vector<PasswordEntry>& entries) {
    std::string blob;
    for (const auto& entry : entries) {
        blob += entry.site + "\n";
        blob += entry.username + "\n";
        blob += entry.password + "\n";
    }
    return blob;
}

// Parses the decrypted blob back into entries
std::vector<PasswordEntry> deserializeEntries(const std::string& blob) {
    std::vector<PasswordEntry> entries;
    std::istringstream stream(blob);
    PasswordEntry entry;
    while (std::getline(stream, entry.site)) {
        if (!std::getline(stream, entry.username)) break;
        if (!std::getline(stream, entry.password)) break;
        entries.push_back(entry);
    }
    return entries;
}

// ---------- Key derivation ----------
// Derives a 32-byte encryption key from the master password + salt using Argon2id
bool deriveKey(const std::string& password, const unsigned char* salt, unsigned char* outKey) {
    return crypto_pwhash(
        outKey, crypto_secretbox_KEYBYTES,
        password.c_str(), password.size(),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_DEFAULT
    ) == 0;
}

// ---------- Encrypt + save ----------
void encryptAndSave(const std::vector<PasswordEntry>& entries, const std::string& masterPassword) {
    std::filesystem::create_directory(DATA_FOLDER);

    std::string blob = serializeEntries(entries);

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    unsigned char key[crypto_secretbox_KEYBYTES];
    if (!deriveKey(masterPassword, salt, key)) {
        std::cout << "Error: key derivation failed (out of memory?).\n";
        return;
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> ciphertext(blob.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(
        ciphertext.data(),
        reinterpret_cast<const unsigned char*>(blob.data()), blob.size(),
        nonce, key
    );

    std::ofstream outFile(DATA_FILE, std::ios::binary | std::ios::trunc);
    if (!outFile) {
        std::cout << "Error: could not open file for saving.\n";
        return;
    }
    outFile.write(reinterpret_cast<const char*>(salt), sizeof(salt));
    outFile.write(reinterpret_cast<const char*>(nonce), sizeof(nonce));
    outFile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    outFile.close();

    // Wipe the key from memory now that we're done with it
    sodium_memzero(key, sizeof(key));
}

// ---------- Load + decrypt ----------
// Returns true on success (entries populated). Returns false on wrong password or missing file.
enum class LoadResult { Success, WrongPassword, NoFile, FileError };

LoadResult decryptAndLoad(const std::string& masterPassword, std::vector<PasswordEntry>& outEntries) {
    std::ifstream inFile(DATA_FILE, std::ios::binary);
    if (!inFile) return LoadResult::NoFile;

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    inFile.read(reinterpret_cast<char*>(salt), sizeof(salt));
    inFile.read(reinterpret_cast<char*>(nonce), sizeof(nonce));
    if (!inFile) return LoadResult::FileError;

    std::vector<unsigned char> ciphertext(
        (std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>()
    );
    if (ciphertext.size() < crypto_secretbox_MACBYTES) return LoadResult::FileError;

    unsigned char key[crypto_secretbox_KEYBYTES];
    if (!deriveKey(masterPassword, salt, key)) return LoadResult::FileError;

    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);
    int result = crypto_secretbox_open_easy(
        decrypted.data(), ciphertext.data(), ciphertext.size(), nonce, key
    );

    sodium_memzero(key, sizeof(key));

    if (result != 0) return LoadResult::WrongPassword;

    std::string blob(decrypted.begin(), decrypted.end());
    outEntries = deserializeEntries(blob);
    return LoadResult::Success;
}

// ---------- Menu actions ----------
void addEntry(std::vector<PasswordEntry>& entries) {
    PasswordEntry entry;
    std::cout << "Site/Service: ";
    std::getline(std::cin, entry.site);
    std::cout << "Username: ";
    std::getline(std::cin, entry.username);
    std::cout << "Password: ";
    std::getline(std::cin, entry.password);
    entries.push_back(entry);
    std::cout << "Entry added.\n\n";
}

void listEntries(const std::vector<PasswordEntry>& entries) {
    if (entries.empty()) {
        std::cout << "No entries yet.\n\n";
        return;
    }
    std::cout << "\n--- Stored Entries ---\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        std::cout << i + 1 << ". " << entries[i].site
            << " | " << entries[i].username
            << " | " << entries[i].password << "\n";
    }
    std::cout << "----------------------\n\n";
}

void deleteEntry(std::vector<PasswordEntry>& entries) {
    listEntries(entries);
    if (entries.empty()) return;
    std::cout << "Enter entry number to delete: ";
    size_t index;
    std::cin >> index;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    if (index >= 1 && index <= entries.size()) {
        entries.erase(entries.begin() + (index - 1));
        std::cout << "Entry deleted.\n\n";
    }
    else {
        std::cout << "Invalid entry number.\n\n";
    }
}

// ---------- Main ----------
int main() {
    if (sodium_init() < 0) {
        std::cout << "Error: libsodium failed to initialize.\n";
        return 1;
    }

    std::vector<PasswordEntry> entries;
    std::string masterPassword;

    bool fileExists = std::filesystem::exists(DATA_FILE);

    if (!fileExists) {
        std::cout << "No vault found - let's create one.\n";
        std::string confirm;
        while (true) {
            masterPassword = promptPassword("Create a master password: ");
            confirm = promptPassword("Confirm master password: ");
            if (masterPassword == confirm && !masterPassword.empty()) break;
            std::cout << "Passwords didn't match (or was empty) - try again.\n";
        }
        encryptAndSave(entries, masterPassword); // saves an empty vault
        std::cout << "Vault created.\n\n";
    }
    else {
        LoadResult result;
        int attempts = 0;
        do {
            masterPassword = promptPassword("Enter your master password: ");
            result = decryptAndLoad(masterPassword, entries);
            if (result == LoadResult::WrongPassword) {
                std::cout << "Incorrect password. Try again.\n";
                attempts++;
            }
        } while (result == LoadResult::WrongPassword && attempts < 5);

        if (result == LoadResult::WrongPassword) {
            std::cout << "Too many failed attempts. Exiting.\n";
            return 1;
        }
        if (result == LoadResult::FileError) {
            std::cout << "Error: vault file is corrupted or unreadable.\n";
            return 1;
        }
        std::cout << "Vault unlocked.\n\n";
    }

    int choice = 0;
    while (choice != 4) {
        std::cout << "=== Password Manager ===\n";
        std::cout << "1. Add entry\n";
        std::cout << "2. View entries\n";
        std::cout << "3. Delete entry\n";
        std::cout << "4. Exit\n";
        std::cout << "Choose an option: ";

        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Please enter a number.\n\n";
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
        case 1:
            addEntry(entries);
            encryptAndSave(entries, masterPassword);
            break;
        case 2:
            listEntries(entries);
            break;
        case 3:
            deleteEntry(entries);
            encryptAndSave(entries, masterPassword);
            break;
        case 4:
            std::cout << "Goodbye!\n";
            break;
        default:
            std::cout << "Invalid option, try again.\n\n";
        }
    }

    // Wipe the master password from memory before exiting
    sodium_memzero(&masterPassword[0], masterPassword.size());

    return 0;
}