# PasswordManager


This is my Password manager that you can install and run locally 
For safety, data is stored local and nothing is present on a cloud.
With this implemention we are using sodium.h to help encrypt our files.

please use follow the directions on https://github.com/microsoft/vcpkg

## Install sodium and Imgui
### Clone vcpkg outside the repo (adjust path as you like)
`git clone https://github.com/microsoft/vcpkg.git /c/dev/vcpkg`
`cd /c/dev/vcpkg`

### Run the bootstrap script - Git Bash can invoke .bat files directly
`./bootstrap-vcpkg.bat`

### Integrate with Visual Studio
`./vcpkg integrate install`

### Install libsodium for 64-bit Windows
`./vcpkg install libsodium:x64-windows`

### Install Imgui for 64-bit Windows
`./vcpkg install imgui[core,glfw-binding,opengl3-binding]:x64-windows`
`./vcpkg install glfw3:x64-windows`

### Verify
Once done you can do:
`./vcpkg list`
you should see the package you have downloaded on to there

## The plan
Master password → encryption key: We never store your master password. Instead, we derive a 256-bit encryption key from it using crypto_pwhash (Argon2id under the hood) combined with a random salt.
Encrypt the whole vault as one blob: Instead of encrypting each password separately, we serialize all your entries into one string and encrypt that as a single unit with crypto_secretbox_easy (XSalsa20-Poly1305 — authenticated encryption).
Wrong-password detection for free: Authenticated encryption includes a built-in "MAC" tag. If you type the wrong master password, decryption will fail loudly instead of silently producing garbage — so we can tell you "wrong password" instead of corrupting your vault.
File format: [salt][nonce][ciphertext] written as raw bytes to data/vault.dat (renaming from .txt since it's now binary, not human-readable).
Masked password input: So your master password doesn't show up as plain text on screen while typing (Windows-only trick using <conio.h>).