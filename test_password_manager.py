"""
Unit tests for password_manager.py
Run with: python -m pytest test_password_manager.py -v
"""

import os
import json
import base64
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from password_manager import (
    derive_key,
    hash_master_password,
    encrypt,
    decrypt,
    generate_password,
    load_vault,
    save_vault,
    add_entry,
    get_entry,
    delete_entry,
    search_entries,
    change_master_password,
    copy_to_clipboard,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def master_password():
    return "MySecurePass123!"


@pytest.fixture
def salt():
    return os.urandom(32)


@pytest.fixture
def enc_key(master_password, salt):
    return derive_key(master_password, salt)


@pytest.fixture
def tmp_vault(tmp_path):
    """Return a path to a temporary vault file."""
    return tmp_path / "test_vault.json"


@pytest.fixture
def empty_vault(salt, master_password, tmp_vault):
    """Create and return an empty initialized vault."""
    pw_hash = hash_master_password(master_password, salt)
    vault = {
        "_meta": {
            "salt": base64.b64encode(salt).decode(),
            "password_hash": pw_hash,
        },
        "entries": {}
    }
    save_vault(vault, tmp_vault)
    return vault, tmp_vault


@pytest.fixture
def vault_with_entry(empty_vault, enc_key):
    """Vault pre-loaded with one entry."""
    vault, path = empty_vault
    vault["entries"]["github.com"] = {
        "username": encrypt("ahmed@example.com", enc_key),
        "password": encrypt("SuperSecret99!", enc_key),
        "notes": encrypt("work account", enc_key),
    }
    save_vault(vault, path)
    return vault, path


# ── Key Derivation & Hashing ──────────────────────────────────────────────────

class TestKeyDerivation:
    def test_derive_key_returns_bytes(self, master_password, salt):
        key = derive_key(master_password, salt)
        assert isinstance(key, bytes)

    def test_derive_key_deterministic(self, master_password, salt):
        key1 = derive_key(master_password, salt)
        key2 = derive_key(master_password, salt)
        assert key1 == key2

    def test_different_salts_produce_different_keys(self, master_password):
        salt1 = os.urandom(32)
        salt2 = os.urandom(32)
        assert derive_key(master_password, salt1) != derive_key(master_password, salt2)

    def test_different_passwords_produce_different_keys(self, salt):
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2

    def test_key_is_valid_fernet_key_length(self, master_password, salt):
        key = derive_key(master_password, salt)
        # Fernet keys are 32 bytes URL-safe base64 encoded = 44 chars
        decoded = base64.urlsafe_b64decode(key)
        assert len(decoded) == 32


class TestPasswordHashing:
    def test_hash_is_deterministic(self, master_password, salt):
        h1 = hash_master_password(master_password, salt)
        h2 = hash_master_password(master_password, salt)
        assert h1 == h2

    def test_different_passwords_different_hashes(self, salt):
        h1 = hash_master_password("password1", salt)
        h2 = hash_master_password("password2", salt)
        assert h1 != h2

    def test_different_salts_different_hashes(self, master_password):
        h1 = hash_master_password(master_password, os.urandom(32))
        h2 = hash_master_password(master_password, os.urandom(32))
        assert h1 != h2

    def test_hash_returns_hex_string(self, master_password, salt):
        h = hash_master_password(master_password, salt)
        assert isinstance(h, str)
        int(h, 16)  # Should not raise — valid hex


# ── Encryption / Decryption ───────────────────────────────────────────────────

class TestEncryptDecrypt:
    def test_encrypt_returns_string(self, enc_key):
        result = encrypt("hello", enc_key)
        assert isinstance(result, str)

    def test_decrypt_roundtrip(self, enc_key):
        original = "my secret password 123!"
        assert decrypt(encrypt(original, enc_key), enc_key) == original

    def test_encrypted_differs_from_plaintext(self, enc_key):
        plain = "hello world"
        assert encrypt(plain, enc_key) != plain

    def test_same_plaintext_different_ciphertext(self, enc_key):
        # Fernet uses a random IV, so same input → different output each time
        c1 = encrypt("hello", enc_key)
        c2 = encrypt("hello", enc_key)
        assert c1 != c2

    def test_wrong_key_raises_error(self, salt):
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        ciphertext = encrypt("secret", key1)
        with pytest.raises(Exception):
            decrypt(ciphertext, key2)

    def test_unicode_roundtrip(self, enc_key):
        original = "مرحبا بالعالم 🔐"
        assert decrypt(encrypt(original, enc_key), enc_key) == original


# ── Password Generator ────────────────────────────────────────────────────────

class TestGeneratePassword:
    def test_correct_length(self):
        for length in [8, 16, 24, 32]:
            assert len(generate_password(length)) == length

    def test_default_length(self):
        assert len(generate_password()) == 16

    def test_no_symbols_option(self):
        import string
        pw = generate_password(100, symbols=False)
        allowed = set(string.ascii_letters + string.digits)
        assert all(c in allowed for c in pw)

    def test_with_symbols_contains_variety(self):
        # Over 200 chars, symbols should appear
        pw = generate_password(200, symbols=True)
        has_symbol = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw)
        assert has_symbol

    def test_randomness(self):
        # Two generated passwords should (almost certainly) differ
        assert generate_password(16) != generate_password(16)


# ── Vault I/O ─────────────────────────────────────────────────────────────────

class TestVaultIO:
    def test_save_and_load(self, tmp_vault):
        data = {"_meta": {"salt": "abc"}, "entries": {"test": "value"}}
        save_vault(data, tmp_vault)
        loaded = load_vault(tmp_vault)
        assert loaded == data

    def test_load_nonexistent_returns_empty(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        assert load_vault(path) == {}

    def test_file_permissions(self, tmp_vault):
        save_vault({"_meta": {}, "entries": {}}, tmp_vault)
        mode = oct(tmp_vault.stat().st_mode)[-3:]
        assert mode == "600"


# ── CRUD Operations ───────────────────────────────────────────────────────────

class TestAddEntry:
    def test_add_entry(self, empty_vault, enc_key):
        vault, path = empty_vault
        inputs = ["github.com", "user@test.com", "n", "mysecret", "work"]
        with patch("builtins.input", side_effect=inputs):
            with patch("getpass.getpass", return_value="mysecret"):
                add_entry(vault, enc_key, path)
        assert "github.com" in vault["entries"]

    def test_add_entry_with_generated_password(self, empty_vault, enc_key):
        vault, path = empty_vault
        inputs = ["site.com", "user@test.com", "y", "20", "n", ""]
        with patch("builtins.input", side_effect=inputs):
            add_entry(vault, enc_key, path)
        entry = vault["entries"]["site.com"]
        password = decrypt(entry["password"], enc_key)
        assert len(password) == 20

    def test_add_entry_empty_service_rejected(self, empty_vault, enc_key, capsys):
        vault, path = empty_vault
        with patch("builtins.input", return_value=""):
            add_entry(vault, enc_key, path)
        assert vault["entries"] == {}

    def test_add_entry_persists_to_disk(self, empty_vault, enc_key):
        vault, path = empty_vault
        inputs = ["persist.com", "user@test.com", "n", ""]
        with patch("builtins.input", side_effect=inputs):
            with patch("getpass.getpass", return_value="pass123"):
                add_entry(vault, enc_key, path)
        reloaded = load_vault(path)
        assert "persist.com" in reloaded["entries"]


class TestGetEntry:
    def test_get_existing_entry(self, vault_with_entry, enc_key, capsys):
        vault, path = vault_with_entry
        with patch("builtins.input", side_effect=["github.com", "n"]):
            get_entry(vault, enc_key)
        out = capsys.readouterr().out
        assert "github.com" in out
        assert "ahmed@example.com" in out

    def test_get_nonexistent_entry(self, vault_with_entry, enc_key, capsys):
        vault, _ = vault_with_entry
        with patch("builtins.input", return_value="notreal.com"):
            get_entry(vault, enc_key)
        out = capsys.readouterr().out
        assert "No entry found" in out

    def test_get_partial_match(self, vault_with_entry, enc_key, capsys):
        vault, _ = vault_with_entry
        with patch("builtins.input", side_effect=["github", "n"]):
            get_entry(vault, enc_key)
        out = capsys.readouterr().out
        assert "github.com" in out

    def test_get_empty_vault(self, empty_vault, enc_key, capsys):
        vault, _ = empty_vault
        get_entry(vault, enc_key)
        out = capsys.readouterr().out
        assert "empty" in out.lower()


class TestDeleteEntry:
    def test_delete_existing_entry(self, vault_with_entry):
        vault, path = vault_with_entry
        with patch("builtins.input", side_effect=["github.com", "y"]):
            delete_entry(vault, path)
        assert "github.com" not in vault["entries"]

    def test_delete_cancelled(self, vault_with_entry):
        vault, path = vault_with_entry
        with patch("builtins.input", side_effect=["github.com", "n"]):
            delete_entry(vault, path)
        assert "github.com" in vault["entries"]

    def test_delete_nonexistent(self, vault_with_entry, capsys):
        vault, path = vault_with_entry
        with patch("builtins.input", return_value="notreal.com"):
            delete_entry(vault, path)
        out = capsys.readouterr().out
        assert "No entry found" in out


class TestSearchEntries:
    def test_search_finds_match(self, vault_with_entry, capsys):
        vault, _ = vault_with_entry
        with patch("builtins.input", return_value="github"):
            search_entries(vault)
        out = capsys.readouterr().out
        assert "github.com" in out

    def test_search_case_insensitive(self, vault_with_entry, capsys):
        vault, _ = vault_with_entry
        with patch("builtins.input", return_value="GITHUB"):
            search_entries(vault)
        out = capsys.readouterr().out
        assert "github.com" in out

    def test_search_no_match(self, vault_with_entry, capsys):
        vault, _ = vault_with_entry
        with patch("builtins.input", return_value="zzznomatch"):
            search_entries(vault)
        out = capsys.readouterr().out
        assert "No entries" in out

    def test_search_empty_vault(self, empty_vault, capsys):
        vault, _ = empty_vault
        search_entries(vault)
        out = capsys.readouterr().out
        assert "empty" in out.lower()


class TestChangeMasterPassword:
    def test_change_password_re_encrypts(self, vault_with_entry, enc_key, salt):
        vault, path = vault_with_entry
        new_password = "NewMasterPass456!"
        new_salt = os.urandom(32)

        with patch("getpass.getpass", side_effect=[new_password, new_password]):
            with patch("os.urandom", return_value=new_salt):
                new_key = change_master_password(vault, enc_key, path)

        # Old key should no longer work
        entry = load_vault(path)["entries"]["github.com"]
        with pytest.raises(Exception):
            decrypt(entry["password"], enc_key)

        # New key should work
        assert decrypt(entry["password"], new_key) == "SuperSecret99!"

    def test_change_password_updates_hash(self, vault_with_entry, enc_key):
        vault, path = vault_with_entry
        old_hash = vault["_meta"]["password_hash"]
        new_password = "BrandNewPass789!"

        with patch("getpass.getpass", side_effect=[new_password, new_password]):
            change_master_password(vault, enc_key, path)

        reloaded = load_vault(path)
        assert reloaded["_meta"]["password_hash"] != old_hash


# ── Clipboard ─────────────────────────────────────────────────────────────────

class TestClipboard:
    def test_copy_to_clipboard_success(self):
        import password_manager as pm
        original = pm.CLIPBOARD_AVAILABLE
        pm.CLIPBOARD_AVAILABLE = True
        with patch("password_manager.pyperclip") as mock_clip:
            mock_clip.copy = MagicMock()
            result = copy_to_clipboard("test_password")
            mock_clip.copy.assert_called_once_with("test_password")
        pm.CLIPBOARD_AVAILABLE = original

    def test_copy_to_clipboard_unavailable(self):
        import password_manager as pm
        original = pm.CLIPBOARD_AVAILABLE
        pm.CLIPBOARD_AVAILABLE = False
        result = copy_to_clipboard("test_password")
        assert result is False
        pm.CLIPBOARD_AVAILABLE = original
