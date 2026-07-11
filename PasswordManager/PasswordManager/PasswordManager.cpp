#include <iostream>
#include <vector>
#include <string>
#include <limits>
#include <fstream>
#include <filesystem>

// Path to the local data file (never committed to git - see .gitignore)
const std::string DATA_FOLDER = "data";
const std::string DATA_FILE = "data/vault.txt";

// Represents a single stored password entry
struct PasswordEntry {
    std::string site;
    std::string username;
    std::string password;
};

// Prompts the user and adds a new entry to the vector
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

// Prints all stored entries
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

// Deletes an entry by its displayed number
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

// Writes all entries to the data file, one field per line, 3 lines per entry
void saveEntries(const std::vector<PasswordEntry>& entries) {
    // Make sure the data folder exists before writing into it
    std::filesystem::create_directory(DATA_FOLDER);

    std::ofstream outFile(DATA_FILE);
    if (!outFile) {
        std::cout << "Error: could not open file for saving.\n\n";
        return;
    }

    for (const auto& entry : entries) {
        outFile << entry.site << "\n";
        outFile << entry.username << "\n";
        outFile << entry.password << "\n";
    }

    outFile.close();
}

// Loads entries from the data file, if it exists
std::vector<PasswordEntry> loadEntries() {
    std::vector<PasswordEntry> entries;
    std::ifstream inFile(DATA_FILE);

    if (!inFile) {
        // No file yet - that's fine, just start with an empty vault
        return entries;
    }

    PasswordEntry entry;
    while (std::getline(inFile, entry.site)) {
        if (!std::getline(inFile, entry.username)) break;
        if (!std::getline(inFile, entry.password)) break;
        entries.push_back(entry);
    }

    inFile.close();
    return entries;
}

int main() {
    std::vector<PasswordEntry> entries = loadEntries();
    int choice = 0;

    while (choice != 4) {
        std::cout << "=== Password Manager ===\n";
        std::cout << "1. Add entry\n";
        std::cout << "2. View entries\n";
        std::cout << "3. Delete entry\n";
        std::cout << "4. Exit\n";
        std::cout << "Choose an option: ";

        if (!(std::cin >> choice)) {
            // Input wasn't a number at all - clear the error state
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Please enter a number.\n\n";
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
        case 1:
            addEntry(entries);
            saveEntries(entries);
            break;
        case 2:
            listEntries(entries);
            break;
        case 3:
            deleteEntry(entries);
            saveEntries(entries);
            break;
        case 4:
            std::cout << "Goodbye!\n";
            break;
        default:
            std::cout << "Invalid option, try again.\n\n";
        }
    }

    return 0;
}