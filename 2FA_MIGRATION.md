# 2FA → KYC Migration Notes

This document records all changes made to rebrand the **2FA (Two-Factor Authentication)**
image-upload verification step into **KYC (Know Your Customer) identity verification**
across the Fetlla CTF backend.

> **Scope:** String/label/message level only.
> No DB schema changes, no Python function/class renames, no logic changes.

---

## Files Changed

### 1. `routers/auth.py`

| Type | Before | After |
|------|--------|-------|
| Route path | `POST /auth/2fa` | `POST /auth/kyc-verify` |
| Route path | `GET /auth/get_2factor` | `GET /auth/get_kyc_records` |
| Error message | `"Bearer token missing"` | `"KYC verification requires a valid session token"` |
| Error message | `"Only image files jpeg/png are accepted"` | `"KYC upload: only JPEG/PNG images accepted"` |
| Error message | `"File size should be less than 1MB"` | `"KYC upload: file must be under 1MB"` |

---

### 2. `llm/langchain_llm.py`

| Type | Before | After |
|------|--------|-------|
| Comment | `# Simple logic for TinyLlama 2FA` | `# KYC verification: AI reviews uploaded identity photo EXIF hash` |
| Error detail | `"No EXIF found."` | `"KYC verification failed: no EXIF metadata in uploaded image."` |
| Error detail | `"user_hash not found in EXIF. Found: ..."` | `"KYC verification failed: identity hash missing from image metadata."` |

---

### 3. `llm/llm_2fa.py`

| Type | Before | After |
|------|--------|-------|
| Module docstring header | `--- PROGRAM FLOW ---` | `--- KYC VERIFICATION FLOW ---` |
| System prompt | `"...handles a secure 2FA..."` | `"...handles secure KYC identity verification..."` |
| Print statement | `"PROMPT INJECTION SUCCESSFULL, 2FA PASSED"` | `"PROMPT INJECTION SUCCESSFUL, KYC BYPASSED"` |
| Print statement | `"Hash length is invalid. Hash must be 32 bit."` | `"KYC: identity hash length is invalid. Must be 32 characters."` |
| Print statement | `"Hash does not match our records."` | `"KYC: identity hash does not match records."` |
| Print statement | `"Validation failed. user_hash not found."` | `"KYC verification failed: identity hash not found in image."` |

---

### 4. `llm/tools/login_tools.py`

| Type | Before | After |
|------|--------|-------|
| Tool name | `"two-factor-validate"` | `"kyc-verify"` |
| Tool docstring | `"Validates 2FA and returns an access token."` | `"Validates KYC identity hash and returns an access token."` |
| Return detail | `"Two factor not enabled"` | `"KYC verification not configured for this account"` |
| Return detail | `"Hash does not match our records"` | `"KYC identity hash does not match our records"` |
| Return detail | `"Two factor authentication completed successfully"` | `"KYC identity verification completed successfully"` |
| Tool name | `"two-factor-prompt-validate"` | `"kyc-prompt-bypass"` |
| Tool docstring | `"Bypasses 2FA via prompt injection..."` | `"Bypasses KYC verification via prompt injection..."` |
| Return detail | `"Two factor authentication completed successfully!!!"` | `"KYC identity verification completed successfully!!!"` |

---

## What Was NOT Changed

| Item | Reason |
|------|--------|
| DB table `two_factor` | Would require an Alembic migration — out of scope |
| DB column `user_hash` | Internal field, not user-visible |
| Python class `TwoFactor`, `TwoFactorResponse`, etc. | Internal; renaming would break imports |
| Python function names (`two_factor_validate`, `langgraph_agent_2fa`, etc.) | Internal; not user-visible |
| `main.py`, `internal-app.py` | No 2FA/MFA strings present |
| `dashboard.py`, `status.py` | No 2FA/MFA strings present |
| Login/registration logic | Separate feature, unrelated to KYC step |

---

## Rationale

The CTF challenge flow previously referred to the EXIF-based image verification step as
"2FA", which was narratively incoherent — a newly registered account would have no
pre-existing MFA photo to verify against. Rebranding this step as **KYC identity
verification** makes the scenario realistic: the system is described as an AI-powered
identity check during account activation, consistent with real-world KYC pipelines.
