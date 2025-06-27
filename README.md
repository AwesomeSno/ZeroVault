# 🔐 ZeroVault

**ZeroVault** is a lightweight, encrypted desktop notes application built with **Python**, **Tkinter**, and **Fernet (AES-256 encryption)** from the `cryptography` library.

Designed for privacy-conscious users, ZeroVault stores all notes **locally** in an encrypted JSON file, ensuring total offline security with no cloud dependencies.

---

## 🚀 Features

- 🔑 **Master Password Protection**  
  All notes are locked behind a single passphrase.

- ✍️ **Create & Manage Notes**  
  Write, view, and delete personal notes through a clean UI.

- 🔒 **End-to-End AES-256 Encryption**  
  Notes are encrypted individually using the Fernet symmetric encryption standard.

- 💾 **100% Offline & Local Storage**  
  No internet connection required. All data is saved locally.

- 🖥️ **Cross-Platform Ready**  
  Works on Windows and easily portable to Linux/macOS.

---

## 📁 Project Structure

```

ZeroVault/
├── main.py            # Main application code
├── vault.json         # Local encrypted notes storage
├── README.md          # Project documentation
├── .gitignore         # Ignored files (e.g. venv, **pycache**, vault.json)
└── venv/              # Python virtual environment (optional)


```

---

## 🧪 Installation & Usage

### 📦 Requirements

- Python 3.8 or higher  
- `cryptography` library  
- Tkinter (usually comes with Python)

### ⚙️ Installation

pip install cryptography

### ▶️ Run the Application

python main.py

---

## 🔐 How It Works

1. On launch, the user enters a **master password**.
2. An encryption key is derived from this password.
3. Notes are **encrypted and stored locally** using that key.
4. The app uses `vault.json` to store the encrypted data, which cannot be accessed without the correct passphrase.

---

## 🧾 License

This project is licensed under the **MIT License**. Feel free to use, modify, and share.

---

## 👤 Author

**Harinandan J V**
🔗 [LinkedIn](https://in.linkedin.com/in/snox)
📧 [harinandanjv@gmail.com](mailto:harinandanjv@gmail.com)

---
