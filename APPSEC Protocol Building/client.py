import struct
import socket
import time
import hashlib
import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature, InvalidTag

MAGIC_BYTES = b"SP"
PROTOCOL_VERSION = 2
CIPHER_SUITE_AES256_GCM = 0x0002

MSG_TYPE_CLIENT_HELLO     = 1
MSG_TYPE_SERVER_HELLO     = 2
MSG_TYPE_KEY_UPDATE       = 3
MSG_TYPE_KEY_UPDATE_ACK   = 4
MSG_TYPE_DATA             = 5
MSG_TYPE_ACK              = 6
MSG_TYPE_FINISHED         = 7

HEADER_PREFIX_FORMAT = "!2sBBQIH"
HEADER_FORMAT        = "!2sBBQIH16s"
HEADER_SIZE          = struct.calcsize(HEADER_FORMAT)

# Bounds checking constants
MAX_CLIENT_ID_LEN = 255
MAX_HELLO_LENGTH = 4096
MAX_PUBLIC_KEY_LEN = 1024
MAX_PAYLOAD_LENGTH = 4096

# Load client ID from environment variable
CLIENT_ID = os.environ.get('CLIENT_ID')
if not CLIENT_ID:
    raise ValueError("CLIENT_ID environment variable must be set")

# Check client ID length (when encoded as UTF-8) fits in a single byte length field
cid_bytes = CLIENT_ID.encode('utf-8')
if len(cid_bytes) > MAX_CLIENT_ID_LEN:
    raise ValueError(f"CLIENT_ID too long: {len(cid_bytes)} bytes (max {MAX_CLIENT_ID_LEN})")

# Load PSK database from environment variables (matching server.py logic)
def load_psk_database():
    """Load PSK database from environment variables.
    Expected format: PSK_<client_id>=<base64_encoded_key>
    Example: PSK_client_ahmed=TXlTdXBlclNlY3JldFByZVNoYXJlZEtleTMzQnl0ZXMh
    """
    psk_db = {}
    for key, value in os.environ.items():
        if key.startswith('PSK_'):
            client_id = key[4:]  # Remove 'PSK_' prefix
            try:
                # Decode base64-encoded key
                psk = base64.b64decode(value)
                psk_db[client_id] = psk
            except Exception:
                raise ValueError(f"Invalid base64 in environment variable {key}")
    return psk_db

# Load PSK database
PSK_DATABASE = load_psk_database()
PSK = PSK_DATABASE.get(CLIENT_ID)
if not PSK:
    raise ValueError(f"PSK for client {CLIENT_ID} not found in environment variables (expected variable PSK_{CLIENT_ID})")

WINDOW_SIZE = 64
MAX_CLOCK_SKEW_SECONDS = 30

class InMemoryReplayWindow:
    def __init__(self, window_size=64):
        self.window_size = window_size
        self.max_seq = 0
        self.bitmap = 0

    def is_valid(self, seq_num):
        if seq_num == 0:
            return False
        if seq_num > self.max_seq:
            return True
        diff = self.max_seq - seq_num
        if diff >= self.window_size:
            return False
        if (self.bitmap & (1 << diff)) != 0:
            return False
        return True

    def commit(self, seq_num):
        if seq_num > self.max_seq:
            shift = seq_num - self.max_seq
            if shift >= self.window_size:
                self.bitmap = 1
            else:
                self.bitmap = ((self.bitmap << shift) | 1) & ((1 << self.window_size) - 1)
            self.max_seq = seq_num
        else:
            diff = self.max_seq - seq_num
            if diff < self.window_size:
                self.bitmap |= (1 << diff)

def compute_hmac(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac(key, data, expected_hmac):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    h.verify(expected_hmac)

def derive_directional_keys(master_secret, info_context=b"custom secure protocol directional keys v3"):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=info_context
    )
    derived = hkdf.derive(master_secret)
    return derived[:32], derived[32:]

def derive_nonce(seq_num):
    return struct.pack("!Q", seq_num) + b"\x00" * 4

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def send_secure_packet(sock, aesgcm, msg_type, raw_payload, seq_num):
    timestamp = int(time.time())
    nonce = derive_nonce(seq_num)
    aad = struct.pack(HEADER_PREFIX_FORMAT, MAGIC_BYTES, PROTOCOL_VERSION, msg_type, seq_num, timestamp, len(raw_payload))
    encrypted_data = aesgcm.encrypt(nonce, raw_payload, aad)
    ciphertext = encrypted_data[:-16]
    gcm_tag = encrypted_data[-16:]
    header = struct.pack(HEADER_FORMAT, MAGIC_BYTES, PROTOCOL_VERSION, msg_type, seq_num, timestamp, len(ciphertext), gcm_tag)
    sock.sendall(header + ciphertext)

def receive_secure_packet(sock, aesgcm, replay_window):
    header_bytes = recv_exact(sock, HEADER_SIZE)
    if not header_bytes:
        return None, None

    try:
        magic, version, msg_type, seq_num, timestamp, payload_len, gcm_tag = struct.unpack(HEADER_FORMAT, header_bytes)
    except struct.error:
        print("[-] Client: Corrupted header received from Server.")
        return None, None

    if magic != MAGIC_BYTES or version != PROTOCOL_VERSION:
        return None, None

    if abs(int(time.time()) - timestamp) > MAX_CLOCK_SKEW_SECONDS:
        print("[-] Client: Expired timestamp from server!")
        return None, None

    if not replay_window.is_valid(seq_num):
        print(f"[-] Client: Replayed server packet detected! Seq: {seq_num}")
        return None, None

    # Bounds check for payload length
    if payload_len > MAX_PAYLOAD_LENGTH:
        print(f"[-] Client: Payload length {payload_len} exceeds maximum {MAX_PAYLOAD_LENGTH}")
        return None, None

    ciphertext = recv_exact(sock, payload_len)
    if not ciphertext:
        return None, None

    aad = struct.pack(HEADER_PREFIX_FORMAT, magic, version, msg_type, seq_num, timestamp, payload_len)
    nonce = derive_nonce(seq_num)

    try:
        decrypted_payload = aesgcm.decrypt(nonce, ciphertext + gcm_tag, aad)
    except InvalidTag:
        print("[-] Client: Tampering detected on Server packet!")
        return None, None

    replay_window.commit(seq_num)
    return msg_type, decrypted_payload

def perform_client_handshake(client_socket):
    try:
        client_private_key = ec.generate_private_key(ec.SECP256R1())
        client_pub_bytes = client_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        cid_bytes = CLIENT_ID.encode('utf-8')
        prefix_id = struct.pack("!B", len(cid_bytes)) + cid_bytes
        hello_prefix = prefix_id + struct.pack("!BHH", PROTOCOL_VERSION, CIPHER_SUITE_AES256_GCM, len(client_pub_bytes)) + client_pub_bytes

        hmac_c = compute_hmac(PSK, b"CLIENT_HELLO" + hello_prefix)
        client_hello_msg = hello_prefix + hmac_c

        client_socket.sendall(struct.pack("!H", len(client_hello_msg)) + client_hello_msg)

        len_bytes = recv_exact(client_socket, 2)
        if not len_bytes:
            return None, None
        server_hello_len = struct.unpack("!H", len_bytes)[0]

        # Bounds check for server hello length
        if server_hello_len < 37 or server_hello_len > MAX_HELLO_LENGTH:
            print(f"[-] Client: Server hello length {server_hello_len} out of bounds")
            return None, None

        server_hello_msg = recv_exact(client_socket, server_hello_len)
        if not server_hello_msg or len(server_hello_msg) < server_hello_len:
            return None, None

        server_version, server_cipher, server_pub_len = struct.unpack("!BHH", server_hello_msg[:5])
        if server_version != PROTOCOL_VERSION or server_cipher != CIPHER_SUITE_AES256_GCM:
            return None, None

        # Bounds check for public key length
        if server_pub_len > MAX_PUBLIC_KEY_LEN:
            print(f"[-] Client: Server public key length {server_pub_len} exceeds maximum {MAX_PUBLIC_KEY_LEN}")
            return None, None
        if len(server_hello_msg) < 5 + server_pub_len:
            print(f"[-] Client: Server hello message too short for public key length {server_pub_len}")
            return None, None

        server_pub_bytes = server_hello_msg[5 : 5+server_pub_len]
        server_hmac = server_hello_msg[5+server_pub_len :]

        expected_srv_payload = b"SERVER_HELLO" + struct.pack("!BHH", server_version, server_cipher, server_pub_len) + server_pub_bytes + client_pub_bytes
        try:
            verify_hmac(PSK, expected_srv_payload, server_hmac)
        except InvalidSignature:
            return None, None

        server_public_key = load_der_public_key(server_pub_bytes)
        shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)

        transcript = (cid_bytes +
                      struct.pack("!BHH", PROTOCOL_VERSION, CIPHER_SUITE_AES256_GCM, len(client_pub_bytes)) +
                      client_pub_bytes +
                      server_hello_msg[:5+server_pub_len])
        transcript_hash = hashlib.sha256(transcript).digest()
        hkdf_info = b"HANDSHAKE_TRANSCRIPT:" + transcript_hash

        cli_key, srv_key = derive_directional_keys(shared_secret, info_context=hkdf_info)
        return cli_key, srv_key
    except (struct.error, IndexError, ValueError) as e:
        print(f"[-] Client: Handshake error: {e}")
        return None, None

def run_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 9999))

    print("[*] Performing Authenticated Handshake...")
    cli_write_key, srv_write_key = perform_client_handshake(client)
    if not cli_write_key:
        print("[-] Handshake Failed!")
        return

    cli_aesgcm = AESGCM(cli_write_key)
    srv_aesgcm = AESGCM(srv_write_key)
    srv_replay_window = InMemoryReplayWindow(window_size=WINDOW_SIZE)
    cli_tx_seq = 1

    send_secure_packet(client, cli_aesgcm, MSG_TYPE_FINISHED, b"CLIENT_FINISHED", cli_tx_seq)
    cli_tx_seq += 1

    msg_type, response = receive_secure_packet(client, srv_aesgcm, srv_replay_window)
    if msg_type != MSG_TYPE_FINISHED or response != b"SERVER_FINISHED":
        print("[-] Key confirmation failed with server!")
        client.close()
        return

    print("[+] Handshake and Key Confirmation Successful!")

    messages = [
        "First message - Key Confirmation Passed!",
        "Second message - Testing Symmetrical Rekey Ratchet!",
    ]

    for msg in messages:
        print(f"\n[Client] Sending: '{msg}'")
        send_secure_packet(client, cli_aesgcm, MSG_TYPE_DATA, msg.encode(), cli_tx_seq)
        cli_tx_seq += 1

        msg_type, response = receive_secure_packet(client, srv_aesgcm, srv_replay_window)
        if response:
            print(f"[Client] Server Response: {response.decode()}")

    print("\n[Rekey] Initiating Key Update Exchange with Fresh ECDH...")
    cli_rekey_priv = ec.generate_private_key(ec.SECP256R1())
    cli_rekey_pub_bytes = cli_rekey_priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    send_secure_packet(client, cli_aesgcm, MSG_TYPE_KEY_UPDATE, cli_rekey_pub_bytes, cli_tx_seq)
    cli_tx_seq += 1

    msg_type, srv_rekey_pub_bytes = receive_secure_packet(client, srv_aesgcm, srv_replay_window)
    if msg_type == MSG_TYPE_KEY_UPDATE_ACK:
        srv_rekey_pub = load_der_public_key(srv_rekey_pub_bytes)
        dh_secret = cli_rekey_priv.exchange(ec.ECDH(), srv_rekey_pub)

        rekey_master = cli_write_key + srv_write_key + dh_secret
        cli_write_key, srv_write_key = derive_directional_keys(rekey_master, info_context=b"rekey_ratchet_v1")

        cli_aesgcm = AESGCM(cli_write_key)
        srv_aesgcm = AESGCM(srv_write_key)

        srv_replay_window = InMemoryReplayWindow(window_size=WINDOW_SIZE)
        cli_tx_seq = 1
        print("[Rekey] Key Update Completed Successfully!")

    post_rekey_msg = "Message sent after full symmetrical key ratchet!"
    print(f"\n[Client] Sending Post-Rekey: '{post_rekey_msg}'")
    send_secure_packet(client, cli_aesgcm, MSG_TYPE_DATA, post_rekey_msg.encode(), cli_tx_seq)

    msg_type, response = receive_secure_packet(client, srv_aesgcm, srv_replay_window)
    if response:
        print(f"[Client] Server Response: {response.decode()}")

    client.close()

if __name__ == "__main__":
    run_client()