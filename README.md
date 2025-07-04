🔐 FilenameGuard: Context-Bound File Encryption

🧩 What is FilenameGuard?

FilenameGuard is a lightweight encryption tool that introduces a new concept in data protection: your file’s name becomes part of the encryption key.

Even if the file is renamed, relocated under a different name, or the attacker correctly guesses your password — decryption will fail unless the original filename is preserved.

This adds a unique contextual binding layer to encryption, improving security and tamper resistance with zero added complexity.

🌟 Feature Summary

🔐 Filename-dependent key derivation
The encryption key is derived from:

SHA-256(password + filename) 

🚫 Fails on rename If the file name changes, decryption will fail even with the correct password.

✅ Minimal & fast Simple CLI-based tool written in Rust using AES-256-CBC with block-modes.

🔐 Consistent file integrity Tied identity to filename enhances trust, traceability, and prevents casual tampering.

💡 Why Does It Matter?

"Billions of files are renamed, copied, and mishandled every day — but encryption doesn't care. What if it did?"

FilenameGuard introduces encryption that cares about context. It's a tiny shift in perspective with huge implications for digital trust, file identity, and leak prevention.

It makes renaming a file a security event, not a trivial change.

📦 How It Works

🔐 Encryption

encrypt <file_path> <password> 

Derives a key from the password + file name.

Encrypts the file with AES-256-CBC.

Saves the result as <original_filename>.enc

🔓 Decryption

decrypt <file_path.enc> <password> 

Extracts original filename.

Regenerates key using filename + password.

If filename was changed → decryption fails.

🧠 Visual Summary

Password + Filename ──► SHA-256 ──► Key ──► AES Encrypt ▲ │ │ ▼ Filename mismatch = decryption failure ❌ 

✨ Comparison

| Feature               | Traditional Encryption | FilenameGuard       |
|-----------------------|------------------------|----------------------|
| Context sensitivity   | ❌ None                | ✅ Yes              |
| Rename protection     | ❌ Vulnerable          | ✅ Enforced by design |
| Identity binding      | 🔄 Basic (password)     | 🔒 Strong (filename) |
| Conceptual novelty    | 🔁 Common              | 🌟 Original Idea     |


🚀 Use Cases

Personal files with sensitive names (e.g., my-wallet.txt)

Tamper-evident backups

Identity-linked file sharing

Developer tools that enforce filename integrity

Context-bound data in secure systems

📚 How to Build & Run

Install Rust:

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh 

Build:

cargo build --release 

Run:

./target/release/filenameguard encrypt secret.txt mypassword ./target/release/filenameguard decrypt secret.txt.enc mypassword 

🧪 About the Innovation

"What if renaming the file broke the encryption?"
That question sparked this tool.

FilenameGuard brings a fresh idea to encryption — one that’s intuitive, original, and rarely explored in commercial or academic products.

👨‍💻 Author & License

Created by Lux (Ali)
📧 Contact: mindofluxx@gmail.com

MIT License © 2025 Lux (Ali)

