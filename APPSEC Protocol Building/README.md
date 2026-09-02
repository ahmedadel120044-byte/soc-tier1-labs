# APPSEC Secure Protocol - Custom Hardened Application-Layer Protocol

A custom secure communication protocol implementing mutual authentication, forward secrecy, and robust cryptographic protections at the application layer.

## 🔒 Security Architecture

This protocol implements multiple layers of security to protect against various attack vectors:

### **Mutual Authentication via HMAC-PSK**
- Both client and server prove possession of a shared Pre-Shared Key (PSK)
- HMAC-SHA256 used to authenticate all handshake messages
- Prevents man-in-the-middle attacks during connection establishment

### **Ephemeral ECDH on SECP256R1 for Perfect Forward Secrecy (PFS)**
- Elliptic Curve Diffie-Hellman key exchange using the SECP256R1 curve
- Ephemeral keys generated for each session
- Compromise of long-term keys does not compromise past session keys

### **HKDF RFC 5869 with Transcript-Hash Binding**
- HMAC-based Key Derivation Function (HKDF) following RFC 5869
- Input keying material includes the full handshake transcript hash
- Ensures keys are bound to the specific handshake context
- Provides key separation for different purposes (encryption vs authentication)

### **AES-256-GCM AEAD**
- Authenticated Encryption with Associated Data using AES-256 in GCM mode
- Provides both confidentiality and integrity guarantees
- Associated Data includes protocol metadata for binding
- Resistance to tampering and replay attacks

### **Anti-Replay Sliding Window**
- 64-bit sequence numbers with sliding window replay protection
- Window size of 64 packets
- Prevents attackers from capturing and retransmitting valid packets

### **Dynamic Rekeying / DH Ratchet**
- Periodic key renewal using fresh ECDH exchanges
- Combines old keys with new Diffie-Hellman shared secret
- Provides forward and future secrecy within a long-lived connection
- Limits the amount of data encrypted with any single key

## 📁 Project Structure

```
APPSEC Protocol Building/
├── client.py          # Client implementation
├── server.py          # Server implementation
├── generate_psk.py    # PSK generation utility
├── requirements.txt   # Python dependencies
├── .env.example       # Environment variables template
├── .gitignore         # Git ignore rules
└── README.md          # This file
```

## ⚙️ Setup & Usage Instructions

### **1. Installing Dependencies**

```bash
# Clone or copy this repository
cd APPSEC Protocol Building

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

### **2. Generating a Pre-Shared Key (PSK)**

```bash
# Generate a secure 32-byte base64-encoded key
python generate_psk.py

# Output example:
# Generated secure PSK (base64-encoded 32 bytes):
# MGW12q2nooO6/C6vkq5k7FNRCFCHoLaZ0yq5Ps0Ov1Y=
#
# To use this key:
# 1. Copy the base64 string above
# 2. Add to your .env file as: PSK_<CLIENT_ID>=<base64_string>
#    Example: PSK_client_ahmed=YOUR_GENERATED_KEY_HERE
```

### **3. Setting Environment Variables**

Create a `.env` file (based on `.env.example`):

```bash
cp .env.example .env
# Edit .env to add your actual values
```

**Example `.env` file:**
```bash
# Client identifier (must match between client and server)
CLIENT_ID=client_ahmed

# Pre-Shared Key for the client (base64 encoded 32-byte key)
# Format: PSK_<CLIENT_ID>=<base64_key>
PSK_client_ahmed=MGW12q2nooO6/C6vkq5k7FNRCFCHoLaZ0yq5Ps0Ov1Y=
```

### **4. Running the Protocol**

**In one terminal (Server):**
```bash
# Ensure environment variables are loaded
# Option 1: Using python-dotenv (if installed)
# Option 2: Export directly or use .env with your shell

# Run server
python server.py
```

**In another terminal (Client):**
```bash
# Use the SAME environment variables as the server
python client.py
```

### **5. Expected Output**

When running correctly, you should see:

**Server Output:**
```
[+] Hardened Secure Protocol Server running on 127.0.0.1:9999
[DEBUG] Loaded PSK for clients: ['client_ahmed']
[+] Handshake Authenticated with ('127.0.0.1', XXXXX)
[+] Key Confirmation (Finished) Passed with ('127.0.0.1', XXXXX)
[Data] Message received: 'First message - Key Confirmation Passed!'
[Data] Message received: 'Second message - Testing Symmetrical Rekey Ratchet!'
[Rekey] Received KEY_UPDATE from ('127.0.0.1', XXXXX). Performing DH Ratchet...
[Rekey] Key Ratchet Completed Successfully with ('127.0.0.1', XXXXX)!
[Data] Message received: 'Message sent after full symmetrical key ratchet!'
```

**Client Output:**
```
[*] Performing Authenticated Handshake...
[+] Handshake and Key Confirmation Successful!

[Client] Sending: 'First message - Key Confirmation Passed!'
[Client] Server Response: ACK_PROCESSED

[Client] Sending: 'Second message - Testing Symmetrical Rekey Ratchet!'
[Client] Server Response: ACK_PROCESSED

[Rekey] Initiating Key Update Exchange with Fresh ECDH...
[Rekey] Key Update Completed Successfully!

[Client] Sending Post-Rekey: 'Message sent after full symmetrical key ratchet!'
[Client] Server Response: ACK_PROCESSED
```

## 🔐 Security Properties

| Property | Mechanism | Protection Against |
|----------|-----------|-------------------|
| **Authentication** | HMAC-PSK | Impersonation, MITM |
| **Confidentiality** | AES-256-GCM | Eavesdropping |
| **Integrity** | AES-256-GCM + HMAC | Tampering |
| **Forward Secrecy** | Ephemeral ECDH | Future key compromise |
| **Future Secrecy** | DH Ratchet | Current key compromise |
| **Replay Resistance** | Sliding Window | Packet replay |
| **Key Separation** | HKDF + Transcript Hash | Key misuse |
| **DoS Resistance** | Rate Limiting, Timeouts | Resource exhaustion |

## 🛠️ Customization

### **Changing Cryptographic Parameters**
- Modify `CIPHER_SUITE_AES256_GCM` constants if needed
- Adjust `WINDOW_SIZE` for replay protection (default: 64)
- Change `MAX_CLOCK_SKEW_SECONDS` for timestamp validation (default: 30)

### **Protocol Messages**
- Message types are defined as constants at the top of both files
- Application messages can be modified in the `messages` list in `run_client()`

### **Key Derivation Context**
- The `info_context` parameter in `derive_directional_keys()` can be changed
- Different contexts for different protocol versions or variants

## ⚠️ Important Security Notes

1. **Never commit real PSKs**: Always use `.env.example` and keep `.env` private
2. **Key Management**: In production, use a proper key management system
3. **Side-channel Protection**: This implementation uses constant-time operations where possible, but consider additional hardening for high-threat environments
4. **Library Updates**: Keep the `cryptography` package updated for security patches
5. **Network Security**: This secures the application layer; consider TLS at the transport layer for additional protection in untrusted networks

## 📚 References

- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tools.ietf.org/html/rfc5869)
- [SECP256R1 Elliptic Curve](https://www.secg.org/sec2-v2.pdf)
- [NIST SP 800-56A: Recommendation for Pair-Wise Key Establishment Schemes](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final)
- [AES-GCM Mode of Operation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

---

*Built for educational and security research purposes. Always conduct security testing in authorized environments only.*