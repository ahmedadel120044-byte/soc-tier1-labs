#!/usr/bin/env python3
"""
Generate a secure random Pre-Shared Key (PSK) for the APPSEC Secure Protocol.
Outputs a base64-encoded 32-byte key suitable for use in .env file.
"""

import secrets
import base64

def generate_psk():
    """Generate a cryptographically secure random 32-byte key and encode it in base64."""
    # Generate 32 random bytes (256 bits) using secrets module
    random_bytes = secrets.token_bytes(32)

    # Encode the bytes in base64 for storage/transmission
    base64_key = base64.b64encode(random_bytes).decode('utf-8')

    return base64_key

if __name__ == "__main__":
    psk = generate_psk()
    print(f"Generated secure PSK (base64-encoded 32 bytes):")
    print(f"{psk}")
    print()
    print("To use this key:")
    print("1. Copy the base64 string above")
    print("2. Add to your .env file as: PSK_<CLIENT_ID>=<base64_string>")
    print("   Example: PSK_client_ahmed=YOUR_GENERATED_KEY_HERE")