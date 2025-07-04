
---

# 🔐✨ NameLock: Context-Bound File Encryption ✨🔐

---

## 🧩 What is NameLock?

**NameLock** is a lightweight Rust-based encryption tool introducing a novel concept:  
**your file’s name** becomes part of the encryption key.

Even if someone renames or relocates the file — or guesses your password correctly —  
**decryption will fail** unless the original filename is preserved.

This adds a unique *contextual binding layer* to encryption, enhancing tamper resistance without added complexity.

---

## 🌟 Key Features

- 🔐 **Filename-dependent key derivation**  
  The encryption key is derived from:  
  ```text
  SHA-256(password + filename)

🚫 Fails on rename
Decryption fails if the file is renamed, even with the correct password.

⚡ Minimal & fast
CLI tool using AES-256-CBC and HMAC-SHA256, written in Rust.

🛡️ Integrity tied to identity
The filename becomes part of the trust model — any change is detectable.



---

💡 Why It Matters

> "Billions of files are renamed, copied, and mishandled every day — and encryption doesn’t care. What if it did?"



NameLock introduces encryption that cares about context.
It transforms a filename into a meaningful part of a file's identity and security.

This shift creates tamper-evident, identity-bound encrypted files, preventing misuse, leaks, and confusion.


---

📦 How It Works

🔐 Encrypt

nameLock encrypt <file_path> <password>

Derives key from SHA-256(password + filename)

Encrypts file with AES-256-CBC

Saves output as <original_filename>.enc



---

🔓 Decrypt

nameLock decrypt <file_path>.enc <password>

Extracts original filename

Derives key from password + filename

Fails if filename doesn't match original



---

🧠 Visual Summary

Password + Filename
        │
     SHA-256
        │
       Key
        │
   AES-256-CBC
        ▲
        │
Decryption fails if filename changed ❌


---

✨ Feature Comparison

Feature	Traditional Encryption	NameLock

Context Awareness	❌ None	✅ Yes
Rename Protection	❌ Vulnerable	✅ Enforced by Design
Identity Binding	🔁 Password only	🔒 Password + Filename
Conceptual Originality	🔁 Common	🌟 Innovative Idea



---

🚀 Use Cases

🔐 Files with sensitive names (e.g., wallet.txt)

🔍 Tamper-evident backups

📎 Filename-linked file sharing

🛠️ Developer tools enforcing filename integrity

🔗 Context-bound data security



---

🛠️ Build & Run

1. Install Rust:



curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

2. Build the project:



cargo build --release

3. Encrypt / Decrypt:



./target/release/namelock encrypt secret.txt My$trongPass!
./target/release/namelock decrypt secret.txt.enc My$trongPass!


---

🧪 The Innovation

> “What if renaming a file broke the encryption?”



That question sparked NameLock — a fresh take on encryption design that binds data to its identity and context.


---

👨‍💻 Author & License

Created by Lux (Ali)
Licensed under MIT License © 2025

---
