#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <GLFW/glfw3.h>

#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstring>
#include <sodium.h>

// ---------- File / folder paths ----------
const std::string DATA_FOLDER = "data";
const std::string DATA_FILE = "data/vault.dat";

// ---------- Data model ----------
struct PasswordEntry {
    std::string site;
    std::string username;
    std::string password;
};

// ---------- Serialization ----------
std::string serializeEntries(const std::vector<PasswordEntry>& entries) {
    std::string blob;
    for (const auto& entry : entries) {
        blob += entry.site + "\n";
        blob += entry.username + "\n";
        blob += entry.password + "\n";
    }
    return blob;
}

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
    if (!deriveKey(masterPassword, salt, key)) return;

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> ciphertext(blob.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(
        ciphertext.data(),
        reinterpret_cast<const unsigned char*>(blob.data()), blob.size(),
        nonce, key
    );

    std::ofstream outFile(DATA_FILE, std::ios::binary | std::ios::trunc);
    if (!outFile) return;
    outFile.write(reinterpret_cast<const char*>(salt), sizeof(salt));
    outFile.write(reinterpret_cast<const char*>(nonce), sizeof(nonce));
    outFile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    outFile.close();

    sodium_memzero(key, sizeof(key));
}

// ---------- Load + decrypt ----------
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

// ---------- App state ----------
enum class Screen { Unlock, Vault };

int main() {
    if (sodium_init() < 0) {
        return 1;
    }

    // ---------- GLFW / ImGui setup ----------
    if (!glfwInit()) return 1;

    const char* glsl_version = "#version 130";
    GLFWwindow* window = glfwCreateWindow(900, 600, "Password Manager", nullptr, nullptr);
    if (!window) { glfwTerminate(); return 1; }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    (void)io;
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // ---------- App data ----------
    std::vector<PasswordEntry> entries;
    std::string masterPassword;
    bool vaultFileExists = std::filesystem::exists(DATA_FILE);
    Screen screen = Screen::Unlock;

    // Unlock screen buffers/state
    char unlockPasswordBuf[128] = "";
    char confirmPasswordBuf[128] = "";
    std::string unlockError;

    // Add/Edit form buffers/state
    char formSite[256] = "";
    char formUser[256] = "";
    char formPass[256] = "";
    int editIndex = -1; // -1 means "adding new", >=0 means "editing that index"

    // Reveal-password tracking (only one row revealed at a time)
    int revealedRow = -1;

    // Copy-to-clipboard feedback
    std::string copiedLabel;
    double copiedAt = -100.0;

    // Delete confirmation
    int pendingDeleteIndex = -1;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
        ImGui::Begin("PasswordManagerRoot", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

        if (screen == Screen::Unlock) {
            // ---------- Unlock / Create vault screen ----------
            ImGui::SetCursorPosY(ImGui::GetWindowHeight() * 0.35f);
            float boxWidth = 400.0f;
            float centerX = (ImGui::GetWindowWidth() - boxWidth) * 0.5f;
            ImGui::SetCursorPosX(centerX);
            ImGui::BeginChild("UnlockBox", ImVec2(boxWidth, 220), true);

            if (!vaultFileExists) {
                ImGui::TextWrapped("No vault found. Create a master password to get started.");
                ImGui::Spacing();
                ImGui::Text("New master password:");
                ImGui::InputText("##newpass", unlockPasswordBuf, IM_ARRAYSIZE(unlockPasswordBuf), ImGuiInputTextFlags_Password);
                ImGui::Text("Confirm password:");
                ImGui::InputText("##confirmpass", confirmPasswordBuf, IM_ARRAYSIZE(confirmPasswordBuf), ImGuiInputTextFlags_Password);

                if (ImGui::Button("Create Vault", ImVec2(-1, 0))) {
                    std::string p1 = unlockPasswordBuf;
                    std::string p2 = confirmPasswordBuf;
                    if (p1.empty()) {
                        unlockError = "Password cannot be empty.";
                    }
                    else if (p1 != p2) {
                        unlockError = "Passwords do not match.";
                    }
                    else {
                        masterPassword = p1;
                        entries.clear();
                        encryptAndSave(entries, masterPassword);
                        vaultFileExists = true;
                        unlockError.clear();
                        std::memset(unlockPasswordBuf, 0, sizeof(unlockPasswordBuf));
                        std::memset(confirmPasswordBuf, 0, sizeof(confirmPasswordBuf));
                        screen = Screen::Vault;
                    }
                }
            }
            else {
                ImGui::Text("Enter your master password:");
                ImGui::InputText("##unlockpass", unlockPasswordBuf, IM_ARRAYSIZE(unlockPasswordBuf), ImGuiInputTextFlags_Password);

                bool enterPressed = ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_Enter);

                if (ImGui::Button("Unlock", ImVec2(-1, 0)) || enterPressed) {
                    std::string attempt = unlockPasswordBuf;
                    LoadResult result = decryptAndLoad(attempt, entries);
                    if (result == LoadResult::Success) {
                        masterPassword = attempt;
                        unlockError.clear();
                        std::memset(unlockPasswordBuf, 0, sizeof(unlockPasswordBuf));
                        screen = Screen::Vault;
                    }
                    else if (result == LoadResult::WrongPassword) {
                        unlockError = "Incorrect password.";
                    }
                    else {
                        unlockError = "Vault file error.";
                    }
                }
            }

            if (!unlockError.empty()) {
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", unlockError.c_str());
            }

            ImGui::EndChild();
        }
        else {
            // ---------- Main vault screen ----------
            ImGui::Text("Password Vault");
            ImGui::SameLine(ImGui::GetWindowWidth() - 140);
            if (ImGui::Button("Lock", ImVec2(120, 0))) {
                // Wipe in-memory data and go back to unlock screen
                sodium_memzero(&masterPassword[0], masterPassword.size());
                masterPassword.clear();
                entries.clear();
                revealedRow = -1;
                screen = Screen::Unlock;
            }

            ImGui::Separator();

            if (ImGui::Button("+ Add Entry")) {
                editIndex = -1;
                formSite[0] = '\0';
                formUser[0] = '\0';
                formPass[0] = '\0';
                ImGui::OpenPopup("Entry Form");
            }

            ImGui::Spacing();

            // Temporary "Copied!" confirmation message
            if (ImGui::GetTime() - copiedAt < 1.5) {
                ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "%s", copiedLabel.c_str());
            }
            else {
                ImGui::TextUnformatted("Tip: click a username or password to copy it.");
            }

            bool openEditPopup = false;
            bool openDeletePopup = false;

            if (ImGui::BeginTable("VaultTable", 4,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupColumn("Site / Service", ImGuiTableColumnFlags_WidthStretch, 0.3f);
                ImGui::TableSetupColumn("Username", ImGuiTableColumnFlags_WidthStretch, 0.3f);
                ImGui::TableSetupColumn("Password", ImGuiTableColumnFlags_WidthStretch, 0.25f);
                ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 180.0f);
                ImGui::TableHeadersRow();

                for (int i = 0; i < (int)entries.size(); ++i) {
                    ImGui::TableNextRow();
                    ImGui::PushID(i);

                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextUnformatted(entries[i].site.c_str());

                    ImGui::TableSetColumnIndex(1);
                    if (ImGui::Selectable(entries[i].username.c_str(), false, ImGuiSelectableFlags_None)) {
                        ImGui::SetClipboardText(entries[i].username.c_str());
                        copiedLabel = "Copied username for \"" + entries[i].site + "\"";
                        copiedAt = ImGui::GetTime();
                    }
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("Click to copy username");
                    }

                    ImGui::TableSetColumnIndex(2);
                    const char* passwordDisplay = (revealedRow == i) ? entries[i].password.c_str() : "********";
                    if (ImGui::Selectable(passwordDisplay, false, ImGuiSelectableFlags_None)) {
                        ImGui::SetClipboardText(entries[i].password.c_str());
                        copiedLabel = "Copied password for \"" + entries[i].site + "\"";
                        copiedAt = ImGui::GetTime();
                    }
                    if (ImGui::IsItemHovered()) {
                        ImGui::SetTooltip("Click to copy password");
                    }

                    ImGui::TableSetColumnIndex(3);
                    if (ImGui::SmallButton(revealedRow == i ? "Hide" : "Show")) {
                        revealedRow = (revealedRow == i) ? -1 : i;
                    }
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Edit")) {
                        editIndex = i;
                        strncpy_s(formSite, entries[i].site.c_str(), _TRUNCATE);
                        strncpy_s(formUser, entries[i].username.c_str(), _TRUNCATE);
                        strncpy_s(formPass, entries[i].password.c_str(), _TRUNCATE);
                        openEditPopup = true;
                    }
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Delete")) {
                        pendingDeleteIndex = i;
                        openDeletePopup = true;
                    }

                    ImGui::PopID();
                }

                ImGui::EndTable();
            }

            // Open popups here, OUTSIDE the row PushID scope, so their IDs
            // match the BeginPopupModal calls below regardless of which row triggered them.
            if (openEditPopup) {
                ImGui::OpenPopup("Entry Form");
            }
            if (openDeletePopup) {
                ImGui::OpenPopup("Confirm Delete");
            }

            // ---------- Add / Edit popup ----------
            ImGui::SetNextWindowSize(ImVec2(420, 0), ImGuiCond_Appearing);
            if (ImGui::BeginPopupModal("Entry Form", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::Text(editIndex == -1 ? "Add New Entry" : "Edit Entry");
                ImGui::Separator();

                ImGui::Text("Site / Service");
                ImGui::InputText("##formsite", formSite, IM_ARRAYSIZE(formSite));
                ImGui::Text("Username");
                ImGui::InputText("##formuser", formUser, IM_ARRAYSIZE(formUser));
                ImGui::Text("Password");
                ImGui::InputText("##formpass", formPass, IM_ARRAYSIZE(formPass));

                ImGui::Spacing();

                if (ImGui::Button("Save", ImVec2(120, 0))) {
                    if (editIndex == -1) {
                        PasswordEntry newEntry;
                        newEntry.site = formSite;
                        newEntry.username = formUser;
                        newEntry.password = formPass;
                        entries.push_back(newEntry);
                    }
                    else {
                        entries[editIndex].site = formSite;
                        entries[editIndex].username = formUser;
                        entries[editIndex].password = formPass;
                    }
                    encryptAndSave(entries, masterPassword);
                    ImGui::CloseCurrentPopup();
                }
                ImGui::SameLine();
                if (ImGui::Button("Cancel", ImVec2(120, 0))) {
                    ImGui::CloseCurrentPopup();
                }

                ImGui::EndPopup();
            }

            // ---------- Delete confirmation popup ----------
            if (ImGui::BeginPopupModal("Confirm Delete", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
                if (pendingDeleteIndex >= 0 && pendingDeleteIndex < (int)entries.size()) {
                    ImGui::Text("Delete entry for \"%s\"?", entries[pendingDeleteIndex].site.c_str());
                }
                ImGui::Spacing();
                if (ImGui::Button("Delete", ImVec2(120, 0))) {
                    if (pendingDeleteIndex >= 0 && pendingDeleteIndex < (int)entries.size()) {
                        entries.erase(entries.begin() + pendingDeleteIndex);
                        encryptAndSave(entries, masterPassword);
                        revealedRow = -1;
                    }
                    pendingDeleteIndex = -1;
                    ImGui::CloseCurrentPopup();
                }
                ImGui::SameLine();
                if (ImGui::Button("Cancel", ImVec2(120, 0))) {
                    pendingDeleteIndex = -1;
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }
        }

        ImGui::End();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.08f, 0.08f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    if (!masterPassword.empty()) {
        sodium_memzero(&masterPassword[0], masterPassword.size());
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}