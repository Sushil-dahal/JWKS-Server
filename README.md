# 🔐 JWKS-Server

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Coverage](https://img.shields.io/badge/coverage-%3E80%25-brightgreen.svg)](#)

A robust, RESTful **JSON Web Key Set (JWKS)** server implementation. This project demonstrates how to manage RSA key pairs, handle key rotation/expiration, and provide a standardized endpoint for JWT verification.

---

## 🚀 Features

* **JWKS Endpoint**: Serves public keys in standard JWKS format for easy integration with authentication providers.
* **JWT Authentication**: Issues signed JWTs with proper `kid` (Key ID) headers in the JOSE header.
* **Key Lifecycle Management**: Automatic generation of 2048-bit RSA keys with expiration timestamps.
* **Security Simulation**: Supports an `expired` flag on the `/auth` endpoint to test how consumers handle expired signatures.
* **High Test Coverage**: Includes a comprehensive suite of unit and integration tests (Pytest).

---

## 📂 Project Structure
```text
jwks-server/
├── main.py             # Main Flask/Web server entry point
├── keys.py             # RSA key generation & management logic
├── test_server.py      # Comprehensive test suite
├── requirements.txt    # Python dependencies
└── README.md           # Documentation
```

---

## 🚦 API Reference

### Get Public Keys

**`GET /.well-known/jwks.json`**

Returns a list of all valid, non-expired public keys.

**Success Response:** `200 OK`
```json
{
  "keys": [
    {
      "alg": "RS256",
      "kty": "RSA",
      "use": "sig",
      "kid": "abc123...",
      "n": "base64url-encoded-modulus",
      "e": "AQAB"
    }
  ]
}
```

### Issue JWT

**`POST /auth`**

Generates a signed JWT.

**Query Parameters:**
* `expired` (optional): If set to `true`, the server signs the token with an expired key to test validation failure.

**Success Response:** `200 OK`
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs..."
}
```

---

## 💻 Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/Sushil-dahal/JWKS-Server.git
cd JWKS-Server
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the server
```bash
python main.py
```

The server will start on `http://localhost:8080`.

---

## 🧪 Testing

We maintain a high standard of code quality. Use `pytest` to run the test suite:

**Run all tests:**
```bash
python -m pytest
```


---

## 🛠️ Technical Implementation

* **Key Management**: Generates RSA key pairs using the `cryptography` library. Each key is assigned a unique `kid` and an expiry date.
* **JWT Signing**: Uses `PyJWT` to sign tokens using the `RS256` algorithm.
* **Filtering Logic**: The JWKS endpoint dynamically filters out keys whose expiry timestamp has passed, ensuring only active keys are public.

---


© 2026 Sushil Dahal
