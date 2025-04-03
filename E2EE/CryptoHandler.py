"""
CryptoHandler class handles all cryptographic operations and processes that needed for the server's and
client's communication.
This class uses pycryptodome external library
Static functions are used by client and server
"""
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from constants import *
import ClientsDB
import struct


def generate_rsa_keys(source='Server'):
    """
    Generates RSA public and private keys
    if source is server it will save the public key for client's use
    otherwise only private key will be saved
    """
    print(f'{source} generating RSA keys!')
    key = RSA.generate(RSA_KEY_BITS)
    public_key = key.publickey().export_key(format='PEM')
    private_key = key.export_key(format='PEM')
    try:
        private_key_path = f"{source}_private_key.pem"
        public_key_path = f"{source}_public_key.pem"
        with open(private_key_path, "wb") as f:
            f.write(private_key)
        if source == 'Server':
            with open(public_key_path, "wb") as fl:
                fl.write(public_key)
                return [public_key, private_key]
    except Exception as e:
        raise e
    return public_key


def get_server_public_key():
    """
    Gets server's public key
    Used by client's application only
    """
    try:
        with open("Server_public_key.pem", "rb") as f:
            binary_public_key = f.read()
        return RSA.import_key(binary_public_key)
    except Exception as e:
        raise e


def get_clients_private_key(uid):
    """
    Gets client's private RSA key
    It can be accessed by the client with matching uid only
    """
    try:
        with open(f"{uid}_client_private_key.pem", "rb") as f:
            binary_public_key = f.read()
        return RSA.import_key(binary_public_key)
    except FileNotFoundError as e:
        raise e


def aes_encryption(payload, aes_key):
    """
    Encrypts a payload using AES encryption in CBC mode.
    This function encrypts the provided payload using the given AES key.
    The function generates an initialization vector (IV) for use with CBC mode
    which is returned along with the encrypted payload.

    """
    print('\tstarting AES payload encryption')
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    enc_payload = cipher_aes.encrypt(pad(payload, AES.block_size))
    iv = cipher_aes.iv
    print('\tPayload was encrypted successfully')
    return enc_payload, iv


def verify_sig(public_key, packet_bytes, signature,key=False):
    """
    Verifies the authenticity of a digital signature.
    If key is False - server's signature, otherwise a client's signature
    This function checks if the provided signature is valid for the given data (packet_bytes) using the specified
    public key.
    hashed with SHA-256 before verification.

    """
    print('\tVerifying digital signature...')
    if key:  # In case a client recieved a message from another client, he provides the sender public key
        public_key = RSA.importKey(public_key)
    hashed_msg = SHA256.new(packet_bytes)
    try:
        pkcs1_15.new(public_key).verify(hashed_msg, signature)
        if key:
            print('\tDigital signature was verified!')

        return True
    except Exception:
        raise Exception('The signature is invalid.')


def client_encrypt_asym(clients_phone_num,other_client=None):
    """Used for sever client communication - small payloads only"""
    try:
        print("\tTrying to encrypt payload with RSA...")

        public_key = get_server_public_key() if other_client is None else RSA.importKey(other_client)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_payload = cipher.encrypt(clients_phone_num)
        print('\tPayload was encrypted successfully!')

        return encrypted_payload
    except Exception as e:
        raise Exception(f'While encrypting client\'s payload {e}.')


def client_decrypt_asymmetric(uid, response):
    """Decrypts data using RSA private key encryption"""
    try:
        print("\tTrying to decrypt payload with RSA...")

        client_private_key = get_clients_private_key(uid)
        cipher = PKCS1_OAEP.new(client_private_key)
        decrypted_payload = cipher.decrypt(response)
        print('\tPayload was decrypted successfully!')

        return decrypted_payload
    except Exception as e:
        print(e, 'client_decrypt_asym')


def aes_decryption(aes_key, payload, iv):
    """AES decryption"""
    print("\tTrying to decrypt payload with AES...")
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_payload = unpad(aes_cipher.decrypt(payload), AES.block_size)
    print('\tPayload was decrypted successfully')

    return decrypted_payload

def sign_client_packet(uid, packed_data):
    """Signs the provided packet data using the client's RSA private key."""
    try:
        print("\tSigning packet...")
        client_private_key = get_clients_private_key(uid)
        hashed_data = SHA256.new(packed_data)
        signature = pkcs1_15.new(client_private_key).sign(hashed_data)
        print("\tPacket was signed successfully!")
        return signature
    except FileNotFoundError as e:
        print(f'{RED_START}You are not registered to the app! Please register as a new client.{COLOR_END}')
        return b''



class CryptoHandler:
    """This class handles cryptographic operations for the server"""
    def __init__(self, database: ClientsDB):
        self.database = database
        self.keys = generate_rsa_keys()

    def decrypt_clients_payload_asym(self, encrypted_payload: bytes) -> bytes:  # raises exception
        """
        Handles file decryption: retrieves the AES key of the user from the database, decrypts (AES-CBC) the payload
        and returns the decrypted file's data
        """
        try:
            print("Server: Trying to decrypt client's payload with RSA...")
            server_private_key = self.get_private_key()
            cipher = PKCS1_OAEP.new(server_private_key)
            decrypted_payload = cipher.decrypt(encrypted_payload)
            print('Server: Client\'s payload was decrypted successfully')
            return decrypted_payload
        except Exception as e:
            raise Exception(f'While decrypting clients payload asym {e}')

    def get_private_key(self):
        """Gets the server's private key """
        try:
            with open("Server_private_key.pem", "rb") as f:
                binary_private_key = f.read()
            return RSA.importKey(binary_private_key)
        except Exception as e:
            raise e

    def sign_server_packet(self, packed_data, code, signature):
        """Signing the hashed data of the server response"""
        if code == INIT_REGISTRATION_SUCCEEDED:  # SendBySecureChannel case, signature is not needed
            return b''
        elif code == CLIENT_SEND_MSG_TO_CLIENT:  # The client sends a message to another client, keeps the original sig
            return signature
        print(f"\tSigning on server's packet, code:{code}")
        server_private_key = self.get_private_key()
        hashed_data = SHA256.new(packed_data)
        signature = pkcs1_15.new(server_private_key).sign(hashed_data)
        print(f"\tSignature was created successfully on server's packet {code}")

        return signature

    def verify_sig_from_client(self, uid, client_req, signature, client_key=b'', code=GENERAL_ERROR):
        """
        Verifies the digital signature from a client for a given request.
        This function checks the validity of the client's digital signature for the provided request.
        It imports the client's public key, hashes the request data, and uses the RSA public key to verify
        the provided signature against the hash of the request data.
        """
        try:
            if code in VERIFY_LATER:
                return True
            client_public_key, hashed_msg = self.import_public_key(client_key, uid, client_req)
            pkcs1_15.new(client_public_key).verify(hashed_msg, signature)
            print(f"Signature verified for client's {code} request.\n")
            return True
        except Exception as e:
            print(f'Cannot verify signature {e}; in request {code}')
            return False

    def import_public_key(self, client_key, uid, client_req):
        """Imports client's public key"""
        if client_key:  # handles request 101, the key isn't stored on the DB yet
            client_public_key = struct.unpack(f'<{len(client_key)}s', client_key)[0]
        else:
            client_public_key = self.database.get_data(CLIENTS_TABLE, uid, PUBLIC_KEY_FIELD)
        client_public_key = RSA.import_key(client_public_key)
        hashed_msg = SHA256.new(client_req[:-SIGNATURE_SIZE])
        return client_public_key, hashed_msg

    def generate_aes_key(self, uid, public_key) -> bytes:
        """
        Handles aes key generation: Retrieves the user's public RSA key,Generates AES key to be sent to the client,
        Stores the AES key in the database for a given user,
        Encrypts the AES key using the user's public RSA key and returns it.
        """
        try:
            print(f"\tGenerating AES key for this current session with client {uid}")
            rsa_key = RSA.import_key(public_key)
            aes_key = get_random_bytes(AES_KEY_SIZE)
            self.database.update_entry(CLIENTS_TABLE, uid, AES_KEY_FIELD, aes_key)
            cipher_key = PKCS1_OAEP.new(rsa_key)
            encrypted_aes_key = cipher_key.encrypt(aes_key)
            print(f"\tAES key was generated successfully for client {uid}")
            return encrypted_aes_key
        except Exception as e:
            raise e
