##🔐 NameLock: Context-Bound File Encryption

##🧩 What is NameLock?

NameLock is a lightweight Rust-based encryption tool that introduces a novel concept: your file’s name becomes part of the encryption key.

Even if someone renames or relocates the file — or even guesses your password correctly — decryption will fail unless the original filename is preserved.

This adds a unique contextual binding layer to encryption, enhancing tamper resistance without any added complexity.


---

##🌟 Key Features

🔐 Filename-dependent key derivation
Encryption key is derived from:
SHA-256(password + filename)

🚫 Fails on rename
Decryption fails if the file is renamed, even with the correct password.

⚡ Minimal & fast
CLI-based tool using AES-256-CBC and HMAC-SHA256, written in Rust.

🛡️ Integrity tied to identity
The filename becomes part of the trust model — changes are detectable.



---

##💡 Why It Matters

> “Billions of files are renamed, copied, and mishandled every day — and encryption doesn’t care. What if it did?”



NameLock introduces encryption that cares about context.
It transforms a filename into a meaningful part of a file's identity — and security.

This simple shift creates tamper-evident, identity-bound encrypted files, helping prevent misuse, leaks, and confusion.


---

##📦 How It Works

🔐 Encrypt

namelock encrypt <file_path> <password>

Derives a key from SHA-256(password + filename)
Encrypts the file using AES-256-CBC
Stores the result as <original_filename>.enc


---

#🔓 Decrypt

namelock decrypt <file_path>.enc <password>

Extracts the original filename
Derives the key from password + filename
Decryption fails if filename doesn't match original


---

##🧠 Visual Summary

Password + Filename
    │
    SHA-256
    │
     Key
    │
 AES-256-CBC
    ▲
    │
Decrypt fails if filename changed ❌


---

##✨ Feature Comparison

Feature	Traditional Encryption	NameLock

Context awareness	❌ None	✅ Yes
Rename protection	❌ Vulnerable	✅ Enforced by design
Identity binding	🔁 Basic (password)	🔒 Strong (filename)
Concept originality	🔁 Common	🌟 Innovative idea



---

##🚀 Use Cases

🔐 Files with sensitive names (e.g., wallet.txt)

🔍 Tamper-evident backups

📎 Filename-linked file sharing

🛠️ Dev tools enforcing filename identity

🔗 Context-bound data security



---

##🛠️ Build & Run

1. Install Rust:



curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

2. Build the project:



cargo build --release

3. Encrypt / Decrypt:



./target/release/namelock encrypt secret.txt My$trongPass!
./target/release/namelock decrypt secret.txt.enc My$trongPass!


---

##🧪 The Innovation

> “What if renaming a file broke the encryption?”



That simple question sparked NameLock — a fresh take on encryption design that binds data to its identity and context.

Rarely explored in commercial or academic tools, this idea unlocks new possibilities in digital trust.


---

👨‍💻 Author & License

Created by Lux (Ali)
📧 Email: mindofluxx@gmail.com

Licensed under the MIT License © 2025 Lux (Ali)


---
