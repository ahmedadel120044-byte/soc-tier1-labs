import struct
import socket
import threading
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
MAX_CLIENT_HELLO_LEN = 4096
MAX_PUBLIC_KEY_LEN = 1024

MAX_CLOCK_SKEW_SECONDS = 30
WINDOW_SIZE = 64
MAX_CONCURRENT_CLIENTS = 10
CLIENT_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_CLIENTS)

FAILED_HANDSHAKES = {}
FAILED_LOCK = threading.Lock()
MAX_FAILED_HANDSHAKES = 5
RATE_LIMIT_WINDOW_SEC = 60

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
                print(f"[-] Warning: Invalid base64 in environment variable {key}")
    return psk_db

# Load PSK database from environment variables
PSK_DATABASE = load_psk_database()
print(f"[DEBUG] Loaded PSK for clients: {list(PSK_DATABASE.keys())}")

def is_ip_rate_limited(ip):
    with FAILED_LOCK:
        now = time.time()
        if ip in FAILED_HANDSHAKES:
            count, first_fail_time = FAILED_HANDSHAKES[ip]
            if now - first_fail_time < RATE_LIMIT_WINDOW_SEC:
                if count >= MAX_FAILED_HANDSHAKES:
                    return True
            else:
                del FAILED_HANDSHAKES[ip]
    return False

def record_handshake_failure(ip):
    with FAILED_LOCK:
        now = time.time()
        if ip in FAILED_HANDSHAKES:
            count, first_fail_time = FAILED_HANDSHAKES[ip]
            if now - first_fail_time < RATE_LIMIT_WINDOW_SEC:
                FAILED_HANDSHAKES[ip] = (count + 1, first_fail_time)
            else:
                FAILED_HANDSHAKES[ip] = (1, now)
        else:
            FAILED_HANDSHAKES[ip] = (1, now)

class InMemoryReplayWindow:
    def __init__(self, window_size=64):
        self.window_size = window_size
        self.max_seq = 0
        self.bitmap = 0
        self.lock = threading.Lock()

    def is_valid(self, seq_num):
        with self.lock:
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
        with self.lock:
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
        return None, None

    if magic != MAGIC_BYTES or version != PROTOCOL_VERSION:
        return None, None

    if abs(int(time.time()) - timestamp) > MAX_CLOCK_SKEW_SECONDS:
        return None, None

    if not replay_window.is_valid(seq_num):
        return None, None

    ciphertext = recv_exact(sock, payload_len)
    if not ciphertext:
        return None, None

    aad = struct.pack(HEADER_PREFIX_FORMAT, magic, version, msg_type, seq_num, timestamp, payload_len)
    nonce = derive_nonce(seq_num)

    try:
        decrypted_payload = aesgcm.decrypt(nonce, ciphertext + gcm_tag, aad)
    except InvalidTag:
        return None, None

    replay_window.commit(seq_num)
    return msg_type, decrypted_payload

def perform_server_handshake(client_socket):
    try:
        len_bytes = recv_exact(client_socket, 2)
        if not len_bytes:
            return None, None
        client_hello_len = struct.unpack("!H", len_bytes)[0]

        # Bounds check for client hello length
        if client_hello_len > MAX_CLIENT_HELLO_LEN:
            print("[-] CLIENT_HELLO length too large")
            return None, None

        client_hello_msg = recv_exact(client_socket, client_hello_len)
        if not client_hello_msg or len(client_hello_msg) < 1:
            return None, None

        client_id_len = client_hello_msg[0]
        # Bounds check for client ID length
        if client_id_len > MAX_CLIENT_ID_LEN:
            print("[-] Client ID length too large")
            return None, None
        required_min_len = 1 + client_id_len + 5 + 32
        if len(client_hello_msg) < required_min_len:
            print("[-] Malformed CLIENT_HELLO: Payload too short.")
            return None, None

        try:
            client_id = client_hello_msg[1:1+client_id_len].decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            print("[-] Invalid UTF-8 in Client ID")
            return None, None
        print(f"[DEBUG] Received client_id: '{client_id}'")
        offset = 1 + client_id_len

        client_version, client_cipher, client_pub_len = struct.unpack("!BHH", client_hello_msg[offset:offset+5])
        if client_version != PROTOCOL_VERSION or client_cipher != CIPHER_SUITE_AES256_GCM:
            print("[-] Handshake Aborted: Incompatible Version/Cipher.")
            return None, None

        # Bounds check for public key length
        if client_pub_len > MAX_PUBLIC_KEY_LEN:
            print("[-] Client public key length too large")
            return None, None
        if len(client_hello_msg) < offset + 5 + client_pub_len + 32:
            print("[-] Malformed CLIENT_HELLO: Public key or HMAC missing.")
            return None, None

        psk = PSK_DATABASE.get(client_id)
        if not psk:
            print(f"[-] Unknown Client ID: {client_id}")
            return None, None

        client_pub_bytes = client_hello_msg[offset+5 : offset+5+client_pub_len]
        client_hmac = client_hello_msg[offset+5+client_pub_len :]

        expected_cli_payload = b"CLIENT_HELLO" + client_hello_msg[:offset+5+client_pub_len]
        try:
            verify_hmac(psk, expected_cli_payload, client_hmac)
        except InvalidSignature:
            print("[-] Invalid Client HMAC-PSK!")
            return None, None

        client_public_key = load_der_public_key(client_pub_bytes)
        server_private_key = ec.generate_private_key(ec.SECP256R1())
        server_pub_bytes = server_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        srv_prefix = struct.pack("!BHH", PROTOCOL_VERSION, CIPHER_SUITE_AES256_GCM, len(server_pub_bytes)) + server_pub_bytes
        hmac_s = compute_hmac(psk, b"SERVER_HELLO" + srv_prefix + client_pub_bytes)
        server_hello_msg = srv_prefix + hmac_s

        client_socket.sendall(struct.pack("!H", len(server_hello_msg)) + server_hello_msg)

        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

        transcript = (client_id.encode('utf-8') +
                      struct.pack("!BHH", client_version, client_cipher, client_pub_len) +
                      client_pub_bytes +
                      srv_prefix)
        transcript_hash = hashlib.sha256(transcript).digest()
        hkdf_info = b"HANDSHAKE_TRANSCRIPT:" + transcript_hash

        cli_key, srv_key = derive_directional_keys(shared_secret, info_context=hkdf_info)
        return cli_key, srv_key

    except (struct.error, IndexError, ValueError) as e:
        print(f"[-] Parsing error during Handshake: {e}")
        return None, None

def handle_client(client_socket, addr):
    ip = addr[0]
    client_socket.settimeout(15.0)
    replay_window = InMemoryReplayWindow(window_size=WINDOW_SIZE)

    try:
        cli_write_key, srv_write_key = perform_server_handshake(client_socket)
        if not cli_write_key:
            record_handshake_failure(ip)
            return

        print(f"[+] Handshake Authenticated with {addr}")
        cli_aesgcm = AESGCM(cli_write_key)
        srv_aesgcm = AESGCM(srv_write_key)

        msg_type, payload = receive_secure_packet(client_socket, cli_aesgcm, replay_window)
        if msg_type != MSG_TYPE_FINISHED or payload != b"CLIENT_FINISHED":
            print(f"[-] Key confirmation failed with {addr}")
            record_handshake_failure(ip)
            return

        srv_tx_seq = 1
        send_secure_packet(client_socket, srv_aesgcm, MSG_TYPE_FINISHED, b"SERVER_FINISHED", srv_tx_seq)
        srv_tx_seq += 1
        print(f"[+] Key Confirmation (Finished) Passed with {addr}")

        while True:
            msg_type, decrypted_payload = receive_secure_packet(client_socket, cli_aesgcm, replay_window)
            if msg_type is None:
                break

            if msg_type == MSG_TYPE_KEY_UPDATE:
                print(f"[Rekey] Received KEY_UPDATE from {addr}. Performing DH Ratchet...")
                try:
                    client_rekey_pub = load_der_public_key(decrypted_payload)
                except ValueError:
                    print("[-] Invalid Public Key in Rekey Payload!")
                    break

                srv_rekey_priv = ec.generate_private_key(ec.SECP256R1())
                srv_rekey_pub_bytes = srv_rekey_priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

                send_secure_packet(client_socket, srv_aesgcm, MSG_TYPE_KEY_UPDATE_ACK, srv_rekey_pub_bytes, srv_tx_seq)
                srv_tx_seq += 1

                dh_secret = srv_rekey_priv.exchange(ec.ECDH(), client_rekey_pub)

                rekey_master = cli_write_key + srv_write_key + dh_secret
                new_cli_key, new_srv_key = derive_directional_keys(rekey_master, info_context=b"rekey_ratchet_v1")

                cli_write_key, srv_write_key = new_cli_key, new_srv_key
                cli_aesgcm = AESGCM(cli_write_key)
                srv_aesgcm = AESGCM(srv_write_key)

                replay_window = InMemoryReplayWindow(window_size=WINDOW_SIZE)
                srv_tx_seq = 1
                print(f"[Rekey] Key Ratchet Completed Successfully with {addr}!")
                continue

            print(f"[Data] Message received: {decrypted_payload.decode('utf-8', errors='strict')}")

            ack_msg = b"ACK_PROCESSED"
            send_secure_packet(client_socket, srv_aesgcm, MSG_TYPE_ACK, ack_msg, srv_tx_seq)
            srv_tx_seq += 1

    except socket.timeout:
        print(f"[-] Connection timed out with {addr}")
    finally:
        client_socket.close()
        CLIENT_SEMAPHORE.release()

def run_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 9999))
    server.listen(5)
    print("[+] Hardened Secure Protocol Server running on 127.0.0.1:9999")

    while True:
        try:
            conn, addr = server.accept()
            ip = addr[0]

            if is_ip_rate_limited(ip):
                print(f"[-] Rate limit exceeded for {ip}. Connection dropped immediately.")
                conn.close()
                continue

            if not CLIENT_SEMAPHORE.acquire(blocking=False):
                print(f"[-] Max connections reached. Dropping {addr}")
                conn.close()
                continue

            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            break
    server.close()

if __name__ == "__main__":
    run_server()