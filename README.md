# 🔒 Password Manager CLI

A secure command-line password manager written in Python. Stores encrypted credentials locally using industry-standard cryptography.

## Features

- **AES-256 encryption** via Fernet (symmetric encryption)
- **PBKDF2-SHA256** key derivation with 480,000 iterations (NIST recommended)
- **Master password authentication** with hashed verification
- **Clipboard support** — copy passwords directly without displaying them
- **Search** — find entries by partial or case-insensitive name
- **Cryptographically secure** random password generator
- **Local encrypted vault** stored as a JSON file (`~/.password_vault.json`)
- Add, retrieve, search, list, and delete credential entries
- Change master password (automatically re-encrypts all entries)

## Security Design

```
Master Password
      │
      ▼
PBKDF2-SHA256 (salt + 480k iterations)
      │
      ├─► Encryption Key  →  Fernet(AES-256-CBC + HMAC-SHA256)  →  Vault entries
      │
      └─► Password Hash   →  Stored in vault for authentication
```

- The master password is **never stored** — only a salted hash is kept
- Each entry's username, password, and notes are individually encrypted
- The vault file has `600` permissions (owner read/write only)
- Passwords are generated using Python's `secrets` module (CSPRNG)
- Clipboard copy via `pyperclip` — avoids leaving passwords on-screen

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/password-manager-cli.git
cd password-manager-cli
pip install -r requirements.txt
```

## Usage

```bash
python password_manager.py
```

On first run, you'll be prompted to create a master password. Then:

```
  [1] Add / Update entry
  [2] Get entry
  [3] Search entries
  [4] List all services
  [5] Delete entry
  [6] Generate password
  [7] Change master password
  [0] Exit
```

### Example Session

```
🔑 Master password: ••••••••

  → 1

── Add Entry ──
  Service / website: github.com
  Username / email: ahmed@example.com
  Generate a random password? (y/n): y
  Password length (default 16): 20
  Generated: X#k9@mLp2$Rv!qZ7nW0s
  📋 Password copied to clipboard!
  ✓ 'github.com' saved.
```

## Running Tests

```bash
pip install pytest
python -m pytest test_password_manager.py -v
```

Tests cover: key derivation, hashing, encryption/decryption, password generation, vault I/O, all CRUD operations, search, clipboard, and master password change.

## Project Structure

```
password-manager-cli/
├── password_manager.py     # Main application
├── test_password_manager.py # Unit tests (pytest)
├── requirements.txt
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10+
- `cryptography` — AES encryption
- `pyperclip` — clipboard support
- `pytest` — for running tests

## Disclaimer

This is a personal learning project. For production use, consider a dedicated password manager like Bitwarden or KeePass.

## License

MIT

---

## Web Interface (Streamlit)

```bash
pip install -r requirements.txt
streamlit run app.py
```

Opens at `http://localhost:8501` with a full GUI:
- 🗄️ **Vault tab** — browse, search, show/hide, delete entries
- ➕ **Add Entry tab** — add with inline password generator & strength meter
- 🎲 **Generator tab** — standalone password generator
- ⚙️ **Settings tab** — change master password, lock vault
