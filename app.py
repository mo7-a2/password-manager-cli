"""
Password Manager - Streamlit Web Interface
Run with: streamlit run app.py
"""

import os
import base64
import streamlit as st
from pathlib import Path

from password_manager import (
    derive_key,
    hash_master_password,
    encrypt,
    decrypt,
    generate_password,
    load_vault,
    save_vault,
    ITERATIONS,
)

# ── Page Config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Password Manager",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* ── Background ── */
.stApp {
    background: #0d1117;
    color: #e6edf3;
}

/* ── Hide default Streamlit chrome ── */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 2rem; padding-bottom: 2rem; max-width: 720px; }

/* ── Logo / Title ── */
.pm-header {
    text-align: center;
    padding: 2.5rem 1rem 1.5rem;
}
.pm-header h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 2rem;
    font-weight: 600;
    color: #58a6ff;
    letter-spacing: -0.5px;
    margin: 0;
}
.pm-header p {
    color: #8b949e;
    font-size: 0.9rem;
    margin-top: 0.4rem;
}

/* ── Cards ── */
.pm-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1rem;
}

/* ── Entry row ── */
.entry-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 0.75rem 1rem;
    margin-bottom: 0.5rem;
    transition: border-color 0.2s;
}
.entry-row:hover { border-color: #58a6ff44; }
.entry-service {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.9rem;
    color: #58a6ff;
    font-weight: 600;
}
.entry-user {
    font-size: 0.8rem;
    color: #8b949e;
    margin-top: 2px;
}

/* ── Password field ── */
.pw-display {
    font-family: 'JetBrains Mono', monospace;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 0.6rem 1rem;
    color: #3fb950;
    font-size: 0.95rem;
    letter-spacing: 1px;
    word-break: break-all;
}

/* ── Strength bar ── */
.strength-bar-wrap {
    height: 4px;
    background: #21262d;
    border-radius: 2px;
    margin-top: 6px;
    overflow: hidden;
}
.strength-bar-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.3s, background 0.3s;
}

/* ── Badges ── */
.badge {
    display: inline-block;
    font-size: 0.72rem;
    padding: 2px 8px;
    border-radius: 20px;
    font-weight: 600;
    letter-spacing: 0.3px;
}
.badge-green  { background: #1a4731; color: #3fb950; }
.badge-yellow { background: #3d2f00; color: #d29922; }
.badge-red    { background: #3d0c0c; color: #f85149; }

/* ── Inputs ── */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: #0d1117 !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
    color: #e6edf3 !important;
    font-family: 'Inter', sans-serif !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: #58a6ff !important;
    box-shadow: 0 0 0 3px #58a6ff22 !important;
}

/* ── Buttons ── */
.stButton > button {
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 0.875rem !important;
    transition: all 0.15s !important;
}
.stButton > button[kind="primary"] {
    background: #238636 !important;
    border-color: #2ea043 !important;
    color: #fff !important;
}
.stButton > button[kind="primary"]:hover {
    background: #2ea043 !important;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: #161b22;
    border-radius: 10px;
    padding: 4px;
    gap: 2px;
    border: 1px solid #30363d;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 7px;
    color: #8b949e;
    font-weight: 500;
    font-size: 0.875rem;
    padding: 0.45rem 1rem;
}
.stTabs [aria-selected="true"] {
    background: #21262d !important;
    color: #e6edf3 !important;
}
.stTabs [data-baseweb="tab-border"] { display: none; }
.stTabs [data-baseweb="tab-panel"] { padding-top: 1.25rem; }

/* ── Alerts ── */
.stSuccess, .stError, .stInfo, .stWarning {
    border-radius: 8px !important;
}

/* ── Slider ── */
.stSlider > div > div > div > div { background: #58a6ff !important; }

/* ── Separator ── */
hr { border-color: #21262d; margin: 1.2rem 0; }

/* ── Lock screen ── */
.lock-wrap {
    text-align: center;
    padding: 3rem 1rem;
}
.lock-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
}
.lock-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.6rem;
    font-weight: 600;
    color: #e6edf3;
    margin-bottom: 0.5rem;
}
.lock-sub {
    color: #8b949e;
    font-size: 0.9rem;
    margin-bottom: 2rem;
}

/* ── Stats row ── */
.stat-box {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 1rem;
    text-align: center;
}
.stat-num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.8rem;
    font-weight: 600;
    color: #58a6ff;
}
.stat-label {
    font-size: 0.78rem;
    color: #8b949e;
    margin-top: 2px;
}
</style>
""", unsafe_allow_html=True)

# ── Session State Defaults ────────────────────────────────────────────────────

def init_state():
    defaults = {
        "authenticated": False,
        "enc_key": None,
        "vault": None,
        "show_passwords": {},   # service -> bool
        "gen_password": "",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

# ── Helpers ───────────────────────────────────────────────────────────────────

def reload_vault():
    st.session_state.vault = load_vault()

def password_strength(pw: str) -> tuple[int, str, str]:
    """Returns (score 0-100, label, css_class)."""
    score = 0
    if len(pw) >= 8:  score += 20
    if len(pw) >= 12: score += 15
    if len(pw) >= 16: score += 15
    if any(c.islower() for c in pw): score += 10
    if any(c.isupper() for c in pw): score += 10
    if any(c.isdigit() for c in pw): score += 15
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pw): score += 15
    if score >= 75: return score, "Strong",  "badge-green"
    if score >= 45: return score, "Medium",  "badge-yellow"
    return score,              "Weak",    "badge-red"

def strength_color(score):
    if score >= 75: return "#3fb950"
    if score >= 45: return "#d29922"
    return "#f85149"

# ── Lock Screen ───────────────────────────────────────────────────────────────

def render_lock_screen():
    vault = load_vault()
    is_new = not bool(vault)

    st.markdown("""
    <div class="lock-wrap">
        <div class="lock-icon">🔒</div>
        <div class="lock-title">Password Manager</div>
        <div class="lock-sub">Encrypted Credential Vault</div>
    </div>
    """, unsafe_allow_html=True)

    col = st.columns([1, 2, 1])[1]
    with col:
        if is_new:
            st.info("No vault found — create your master password to get started.")
            pw  = st.text_input("New master password", type="password", key="setup_pw")
            pw2 = st.text_input("Confirm password",    type="password", key="setup_pw2")

            if pw:
                score, label, css = password_strength(pw)
                st.markdown(f"""
                <div class="strength-bar-wrap">
                  <div class="strength-bar-fill" style="width:{score}%;background:{strength_color(score)}"></div>
                </div>
                <span class="badge {css}" style="margin-top:6px;display:inline-block">{label}</span>
                """, unsafe_allow_html=True)

            if st.button("Create Vault", type="primary", use_container_width=True):
                if len(pw) < 8:
                    st.error("Password must be at least 8 characters.")
                elif pw != pw2:
                    st.error("Passwords do not match.")
                else:
                    salt    = os.urandom(32)
                    pw_hash = hash_master_password(pw, salt)
                    new_vault = {
                        "_meta": {
                            "salt": base64.b64encode(salt).decode(),
                            "password_hash": pw_hash,
                        },
                        "entries": {}
                    }
                    save_vault(new_vault)
                    st.session_state.authenticated = True
                    st.session_state.enc_key = derive_key(pw, salt)
                    st.session_state.vault   = new_vault
                    st.rerun()
        else:
            pw = st.text_input("Master password", type="password", key="login_pw")
            if st.button("Unlock", type="primary", use_container_width=True):
                salt        = base64.b64decode(vault["_meta"]["salt"])
                stored_hash = vault["_meta"]["password_hash"]
                if hash_master_password(pw, salt) == stored_hash:
                    st.session_state.authenticated = True
                    st.session_state.enc_key = derive_key(pw, salt)
                    st.session_state.vault   = vault
                    st.rerun()
                else:
                    st.error("Wrong master password.")

# ── Main App ──────────────────────────────────────────────────────────────────

def render_app():
    vault = st.session_state.vault
    key   = st.session_state.enc_key
    entries = vault.get("entries", {})

    # Header
    st.markdown("""
    <div class="pm-header">
        <h1>🔒 Password Manager</h1>
        <p>Encrypted Credential Vault</p>
    </div>
    """, unsafe_allow_html=True)

    # Stats row
    total = len(entries)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f'<div class="stat-box"><div class="stat-num">{total}</div><div class="stat-label">Stored Entries</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="stat-box"><div class="stat-num">AES-256</div><div class="stat-label">Encryption</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="stat-box"><div class="stat-num">PBKDF2</div><div class="stat-label">Key Derivation</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Tabs
    tab_vault, tab_add, tab_gen, tab_settings = st.tabs([
        "🗄️  Vault", "➕  Add Entry", "🎲  Generator", "⚙️  Settings"
    ])

    # ── Tab: Vault ────────────────────────────────────────────────────────────
    with tab_vault:
        if not entries:
            st.markdown("""
            <div style="text-align:center;padding:3rem;color:#8b949e;">
                <div style="font-size:2.5rem;margin-bottom:.75rem">🗃️</div>
                <div style="font-size:1rem">Your vault is empty</div>
                <div style="font-size:.85rem;margin-top:.4rem">Add your first entry in the ➕ tab</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            search = st.text_input("🔍 Search", placeholder="Filter by service name…", label_visibility="collapsed")
            filtered = {s: e for s, e in sorted(entries.items()) if search.lower() in s.lower()} if search else dict(sorted(entries.items()))

            if not filtered:
                st.info(f"No results for '{search}'")
            else:
                for service, entry in filtered.items():
                    username = decrypt(entry["username"], key)
                    password = decrypt(entry["password"], key)
                    notes    = decrypt(entry["notes"], key) if entry["notes"] else ""
                    show_key = f"show_{service}"
                    if show_key not in st.session_state:
                        st.session_state[show_key] = False

                    with st.expander(f"**{service}**  —  {username}"):
                        col_a, col_b = st.columns([3, 1])
                        with col_a:
                            st.markdown("**Username**")
                            st.code(username, language=None)
                            st.markdown("**Password**")
                            if st.session_state[show_key]:
                                score, label, css = password_strength(password)
                                st.markdown(f'<div class="pw-display">{password}</div>', unsafe_allow_html=True)
                                st.markdown(f"""
                                <div class="strength-bar-wrap">
                                  <div class="strength-bar-fill" style="width:{score}%;background:{strength_color(score)}"></div>
                                </div>
                                <span class="badge {css}" style="margin-top:6px;display:inline-block">{label}</span>
                                """, unsafe_allow_html=True)
                            else:
                                st.markdown('<div class="pw-display">••••••••••••••••</div>', unsafe_allow_html=True)
                            if notes:
                                st.markdown("**Notes**")
                                st.caption(notes)

                        with col_b:
                            st.markdown("<br>", unsafe_allow_html=True)
                            toggle_label = "🙈 Hide" if st.session_state[show_key] else "👁 Show"
                            if st.button(toggle_label, key=f"toggle_{service}", use_container_width=True):
                                st.session_state[show_key] = not st.session_state[show_key]
                                st.rerun()
                            if st.button("🗑 Delete", key=f"del_{service}", use_container_width=True):
                                st.session_state[f"confirm_del_{service}"] = True
                                st.rerun()

                        if st.session_state.get(f"confirm_del_{service}"):
                            st.warning(f"Delete **{service}**? This cannot be undone.")
                            dc1, dc2 = st.columns(2)
                            with dc1:
                                if st.button("Yes, delete", key=f"yes_del_{service}", use_container_width=True):
                                    del vault["entries"][service]
                                    save_vault(vault)
                                    st.session_state.vault = vault
                                    st.session_state.pop(f"confirm_del_{service}", None)
                                    st.success(f"'{service}' deleted.")
                                    st.rerun()
                            with dc2:
                                if st.button("Cancel", key=f"cancel_del_{service}", use_container_width=True):
                                    st.session_state.pop(f"confirm_del_{service}", None)
                                    st.rerun()

    # ── Tab: Add Entry ────────────────────────────────────────────────────────
    with tab_add:
        st.markdown("#### Add / Update Entry")

        service  = st.text_input("Service / Website", placeholder="e.g. github.com")
        username = st.text_input("Username / Email",  placeholder="e.g. ahmed@example.com")

        use_gen = st.checkbox("Generate password automatically", value=True)
        if use_gen:
            gc1, gc2 = st.columns([2, 1])
            with gc1:
                gen_len = st.slider("Length", 8, 64, 20)
            with gc2:
                gen_sym = st.checkbox("Symbols", value=True)

            if st.button("🎲 Generate", use_container_width=True):
                st.session_state.gen_password = generate_password(gen_len, symbols=gen_sym)

            if st.session_state.gen_password:
                st.markdown("**Generated Password**")
                score, label, css = password_strength(st.session_state.gen_password)
                st.markdown(f'<div class="pw-display">{st.session_state.gen_password}</div>', unsafe_allow_html=True)
                st.markdown(f"""
                <div class="strength-bar-wrap">
                  <div class="strength-bar-fill" style="width:{score}%;background:{strength_color(score)}"></div>
                </div>
                <span class="badge {css}" style="margin-top:6px;display:inline-block">{label}</span>
                """, unsafe_allow_html=True)
            password = st.session_state.gen_password
        else:
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            if password:
                score, label, css = password_strength(password)
                st.markdown(f"""
                <div class="strength-bar-wrap">
                  <div class="strength-bar-fill" style="width:{score}%;background:{strength_color(score)}"></div>
                </div>
                <span class="badge {css}" style="margin-top:6px;display:inline-block">{label}</span>
                """, unsafe_allow_html=True)

        notes = st.text_area("Notes (optional)", placeholder="Any extra info…", height=80)

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("💾 Save Entry", type="primary", use_container_width=True):
            if not service.strip():
                st.error("Service name is required.")
            elif not password:
                st.error("Password cannot be empty. Generate one or type it in.")
            else:
                vault["entries"][service.strip()] = {
                    "username": encrypt(username.strip(), key),
                    "password": encrypt(password, key),
                    "notes":    encrypt(notes.strip(), key) if notes.strip() else "",
                }
                save_vault(vault)
                st.session_state.vault = vault
                st.session_state.gen_password = ""
                st.success(f"✓ '{service.strip()}' saved successfully!")

    # ── Tab: Generator ────────────────────────────────────────────────────────
    with tab_gen:
        st.markdown("#### Password Generator")
        st.caption("Generate a secure random password without saving it.")

        col1, col2 = st.columns([3, 1])
        with col1:
            g_len = st.slider("Length", 8, 64, 16, key="gen_standalone_len")
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            g_sym = st.checkbox("Symbols", value=True, key="gen_standalone_sym")

        if st.button("🎲 Generate Password", type="primary", use_container_width=True, key="gen_standalone_btn"):
            st.session_state["standalone_pw"] = generate_password(g_len, symbols=g_sym)

        if "standalone_pw" in st.session_state and st.session_state["standalone_pw"]:
            pw = st.session_state["standalone_pw"]
            score, label, css = password_strength(pw)
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("**Your Password**")
            st.markdown(f'<div class="pw-display" style="font-size:1.1rem">{pw}</div>', unsafe_allow_html=True)
            st.markdown(f"""
            <div class="strength-bar-wrap" style="margin-top:10px">
              <div class="strength-bar-fill" style="width:{score}%;background:{strength_color(score)}"></div>
            </div>
            <span class="badge {css}" style="margin-top:8px;display:inline-block">{label} — score {score}/100</span>
            """, unsafe_allow_html=True)
            st.text_input("Copy from here →", value=pw, key="gen_copy_field", label_visibility="collapsed")

    # ── Tab: Settings ─────────────────────────────────────────────────────────
    with tab_settings:
        st.markdown("#### Change Master Password")
        old_pw  = st.text_input("Current master password", type="password", key="chg_old")
        new_pw  = st.text_input("New master password",     type="password", key="chg_new")
        new_pw2 = st.text_input("Confirm new password",    type="password", key="chg_new2")

        if new_pw:
            score, label, css = password_strength(new_pw)
            st.markdown(f"""
            <div class="strength-bar-wrap">
              <div class="strength-bar-fill" style="width:{score}%;background:{strength_color(score)}"></div>
            </div>
            <span class="badge {css}" style="margin-top:6px;display:inline-block">{label}</span>
            """, unsafe_allow_html=True)

        if st.button("🔑 Update Master Password", type="primary", use_container_width=True):
            salt_b      = base64.b64decode(vault["_meta"]["salt"])
            stored_hash = vault["_meta"]["password_hash"]
            if hash_master_password(old_pw, salt_b) != stored_hash:
                st.error("Current master password is incorrect.")
            elif len(new_pw) < 8:
                st.error("New password must be at least 8 characters.")
            elif new_pw != new_pw2:
                st.error("New passwords do not match.")
            else:
                from password_manager import encrypt as pm_encrypt, decrypt as pm_decrypt
                new_salt    = os.urandom(32)
                new_key     = derive_key(new_pw, new_salt)
                new_hash    = hash_master_password(new_pw, new_salt)
                for svc, entry in vault["entries"].items():
                    vault["entries"][svc] = {
                        "username": pm_encrypt(pm_decrypt(entry["username"], key), new_key),
                        "password": pm_encrypt(pm_decrypt(entry["password"], key), new_key),
                        "notes":    pm_encrypt(pm_decrypt(entry["notes"],    key), new_key) if entry["notes"] else "",
                    }
                vault["_meta"]["salt"]          = base64.b64encode(new_salt).decode()
                vault["_meta"]["password_hash"] = new_hash
                save_vault(vault)
                st.session_state.vault   = vault
                st.session_state.enc_key = new_key
                st.success("✓ Master password updated and vault re-encrypted.")

        st.markdown("---")
        st.markdown("#### Session")
        if st.button("🔒 Lock Vault", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.enc_key       = None
            st.session_state.vault         = None
            st.rerun()

    # ── Lock button (top right) ───────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        "<div style='text-align:center;color:#8b949e;font-size:0.78rem'>🔐 Vault is unlocked &nbsp;·&nbsp; Data encrypted with AES-256</div>",
        unsafe_allow_html=True
    )

# ── Router ────────────────────────────────────────────────────────────────────

if st.session_state.authenticated:
    render_app()
else:
    render_lock_screen()
