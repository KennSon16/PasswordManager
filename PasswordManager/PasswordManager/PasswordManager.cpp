#include <iostream>
#include <vector>
#include <string>
#include <limits>

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
    } else {
        std::cout << "Invalid entry number.\n\n";
    }
}

int main() {
    std::vector<PasswordEntry> entries;
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
                break;
            case 2:
                listEntries(entries);
                break;
            case 3:
                deleteEntry(entries);
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