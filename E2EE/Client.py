from ClientResponseHandler import ClientRespHandler
from datetime import datetime
from CryptoHandler import *
from ClientCmdOps import *
from constants import *
import socket
import struct


class Client:
    def __init__(self, num):
        self.phone_number = num
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.establish_connection()
        self.public_key = b''
        self.aes_key = b''
        self.requests_dict = self.make_request_dict()
        self.response_handler = ClientRespHandler(self.phone_number, self._socket,self)

    # =========================== Connection related ===========================

    def establish_connection(self):
        """Handles the client connection request to the server"""
        try:
            self._socket.connect((HOST, DEFAULT_PORT))
        except Exception as e:
            print(f'While connecting to the server {e}')
            return

    def send_message(self, op, recipient_id=0, response=()):
        """Sends a packet to the server"""
        try:
            data = self.client_request(op, recipient_id, response)
            if not data:
                return False
            elif data == 0:
                return True
            self._socket.sendall(data)
            return True
        except Exception as e:
            print(e)

    # =========================== Request Handlers ===========================
    def make_request_dict(self):
        """Creates a dictionary mapping request types to their corresponding handler methods"""
        requests = {
            REGISTER: self.initial_registration,
            S_PUBLIC_KEY: self.otp_public_key,
            GET_RECIPIENT_PUB_KEY: self.get_recipient_public_key,
            CLIENT_SEND_MSG_TO_CLIENT: self.send_message_to_recipient,
            CLIENT_RECONNECT_REQUEST: self.reconnect_request,
            DISCONNECT: self.disconnect
        }
        return requests

    def client_request(self, request_code, recipient_id=0, response=()):
        """Handles client request selection based on code request and the request dict"""
        client_req = self.requests_dict.get(request_code)
        if recipient_id != 0 and recipient_id != SERVER_ID:
            return client_req(recipient_id)
        elif response != ():
            return client_req(response)
        return client_req()

    def initial_registration(self):
        """Handles request code 100, initial registration request for the client"""
        encrypted_phone_number = client_encrypt_asym(struct.pack('<I', self.phone_number))
        return self.init_request(INITIAL_ID, SERVER_ID, REGISTER, len(encrypted_phone_number), encrypted_phone_number)

    def otp_public_key(self, response):
        """
        Handles code request 101,in app OTP verification by getting user's input,
        input has to match to the OTP he got from the sever
        and handles RSA key generation
        """
        otp_from_client = self.get_otp_from_client(response[PAYLOAD_INDEX_FROM_SERVER])
        if otp_from_client == 0:  # otp is not matching
            return b''
        self.public_key = generate_rsa_keys(f'{self.phone_number}_client')
        encrypted_payload = client_encrypt_asym(otp_from_client)
        encrypted_payload += self.public_key  # public key is not encrypted because its public
        return self.init_request(self.phone_number, SERVER_ID, S_PUBLIC_KEY,len(encrypted_payload), encrypted_payload)

    def send_message_to_recipient(self, recipient_id):
        """
        Handles request code 102, sends a message to another client
        Requesting the recipient's public key from the server.
        Encrypting the message with the recipient's public key.
        Sending the encrypted message to the server with the appropriate request code.
        """
        self.send_message(GET_RECIPIENT_PUB_KEY, recipient_id)
        recipient_public_key = self.response_handler.handle_server_response()
        if not recipient_public_key:
            return 0
        message = self.get_message().encode('utf-8')
        encrypted_message = client_encrypt_asym(message,recipient_public_key)
        return self.init_request(self.phone_number, int(recipient_id), CLIENT_SEND_MSG_TO_CLIENT, len(encrypted_message), encrypted_message)

    def get_recipient_public_key(self, recipient_id):
        """
        Handles request code 105, another client's public key request.
        This function sends a request to the server to retrieve the recipient's public key, which
        is required for encrypting a message intended for that recipient. The recipient's ID is
        encrypted using the client's AES key, and the encrypted payload is sent as part of the request
        """
        print(f'Client {self.phone_number} Requesting public key of client client to send a message')
        encrypted_payload, iv = aes_encryption(recipient_id, self.aes_key)
        payload = encrypted_payload+iv
        return self.init_request(self.phone_number, SERVER_ID, GET_RECIPIENT_PUB_KEY, len(payload), payload)

    def disconnect(self):
        """Handles request code 222,disconnection request from the server"""
        print('Disconnecting ... Please wait for a confirmation')
        return self.init_request(self.phone_number, SERVER_ID, DISCONNECT, 0, b'')

    def init_request(self, sender_id, recipient_id, op_code, payload_size, payload):
        """
        Initializes a request by packing the sender and recipient IDs, operation code, payload size,
        timestamp, and payload into a packed binary format.
        Signs the data and adds it to th packet.
        """
        # Format string for struct.pack
        fmt = f'<I I 19s B H {payload_size}s'
        # Timestamp
        date = datetime.now()
        fmt_date = date.strftime('%Y-%m-%d %H:%M:%S')
        timestamp = fmt_date.encode('utf-8')
        # Pack the message
        packed_data = struct.pack(fmt, sender_id, recipient_id, timestamp, op_code, payload_size, payload)
        return self.sign_on_packet(op_code, packed_data)

    def sign_on_packet(self, code, packed_data):
        """Signs the request data """
        if code == REGISTER:
            return packed_data
        signature = sign_client_packet(self.phone_number, packed_data)
        packed_data += struct.pack(f'<{len(signature)}s', signature)
        return packed_data if signature else signature

    # =========================== Client processes ===========================
    def create_new_account(self):
        """
        New account creation process:
        Sends the phone number and receiving an OTP (One Time Password) from the server.
        Verifies the OTP in-app.
        Receives confirmation of successful registration and storing the AES key for encryption.
        """
        try:
            otp_from_server = self.enter_phone_get_OTP()
            self.in_app_otp_verification(otp_from_server)
            self.get_registration_confirmation()
            return True
        except Exception as e:
            print(e)
            return False

    def enter_phone_get_OTP(self):
        self.send_message(REGISTER)
        otp_from_server = self.response_handler.handle_server_response()
        if not otp_from_server:
            raise Exception
        return otp_from_server

    def in_app_otp_verification(self, otp_from_server):
        if not self.send_message(S_PUBLIC_KEY, response=otp_from_server):
            raise Exception("Could not verify OTP, try again later")

    def get_registration_confirmation(self):
        registration_status = self.response_handler.handle_server_response()
        self.aes_key = registration_status
        if not registration_status:
            raise Exception(f'Could not create account for client {self.phone_number}')

    def send_msg_client_to_client(self, recipient_id):
        """Message sending to another client process"""
        print('Message sending to a client process:')
        if self.send_message(CLIENT_SEND_MSG_TO_CLIENT, recipient_id):
            #self.send_message(GET_RECIPIENT_PUB_KEY, recipient_id):
            self.response_handler.handle_server_response()   # sends the message from client

    def reconnect_request(self):
        """
        Handles request code 106, which is used to request reconnection to the server
        by a client. The client sends its phone number, encoded and encrypted, to the server
        to initiate the reconnection process.
        """
        encoded_phone_num = self.encode_client_number(self.phone_number)
        encrypted_payload = client_encrypt_asym(encoded_phone_num)
        return self.init_request(self.phone_number, SERVER_ID, CLIENT_RECONNECT_REQUEST, len(encrypted_payload), encrypted_payload)

    def reconnect(self):
        """Reconnection process"""
        if self.send_message(CLIENT_RECONNECT_REQUEST):
            aes,message_count = self.response_handler.handle_server_response()
            self.aes_key = aes
            return self.response_handler.get_offline_messages(message_count, aes)

    def client_disconnect(self):
        """Handles the disconnection process of the client from the server"""
        try:
            self.send_message(DISCONNECT, SERVER_ID)
            disconnected = self.response_handler.handle_server_response()
            while disconnected != DISCONNECT:
                disconnected = self.response_handler.handle_server_response()
            print(f"Client {self.phone_number} disconnected.")
            return
        except Exception as e:
            print(f"Error closing socket in destructor: {e}")

    # =========================== Utils ===========================
    def get_message(self):
        """Gets a message input from the sending client"""
        msg = input('Type a message: ')
        while len(msg) > MAX_CLIENT_MESSAGE_SIZE:
            print(f'Max size is {MAX_CLIENT_MESSAGE_SIZE}, type a shorter message')
            msg = input('Type a message: ')
        return msg

    def encode_client_number(self, client_num):
        """Encodes client's number"""
        try:
            client_num_str = str(client_num)
            encoded_client_num = client_num_str.encode('utf-8')
            return encoded_client_num
        except Exception as e:
            print(f'While recieve_message_from_other_client {e}')
            return None

    def get_otp_from_client(self,otp_from_server):
        """Gets the OTP input from the user. The user has 5 tries to provide the matching OTP."""
        print(f'New OTP code: {otp_from_server.decode()}. This code is valid for 5 minutes.')
        print(f'{RED_START}DO NOT SHARE THIS CODE WITH ANYONE!!{COLOR_END}')
        OTP_from_client = input('Please enter the password showed in the popup: ').encode('utf-8')
        tries = 4
        while OTP_from_client != otp_from_server and tries > 0:
            print(f'{RED_START}OTP is not correct! You have {tries} more chances to re-enter the password{COLOR_END}')
            OTP_from_client = input('Please enter the OTP: ').encode('utf-8')
            tries-=1
        if otp_from_server == OTP_from_client:
            print("Otp is matching! Waiting for server's approval.")
            return OTP_from_client
        return 0


def main():
    client_operation()


if __name__ == '__main__':
    main()

