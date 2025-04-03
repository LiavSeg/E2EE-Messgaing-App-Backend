"""
Request Handler class handles all client's requests related operations and responses
Included data receiving and sending via socket
"""
import socket
import struct
import random
import constants
from datetime import datetime, timedelta
from ClientsDB import ClientsDB
from CryptoHandler import CryptoHandler, aes_encryption,aes_decryption
import threading
from constants import *


class RequestHandler:
    def __init__(self, client_socket: socket, database: ClientsDB, crypto_handler: CryptoHandler, OTP: dict, connected_clients):
        self.database = database
        self.OTP = OTP
        self.crypto_handler = crypto_handler
        self.client_socket = client_socket
        self.connected_clients = connected_clients
        self.lock = threading.Lock()
        self.request_dict = self.make_request_dict()

        # =========================== Packets handling  ===========================
    def handle_req(self) -> bytes:
        """ Receives a request from the client - a fixed size header followed by a dynamically sized payload
            returns a response for the client according the code request and protocol demands
        """
        try:
            data = self.client_socket.recv(CLIENT_HEADER_SIZE)
            if len(data) == 0:
                return b''
            header = struct.unpack(SERVER_UNP_HEADER_FMT, data)
            payload_size = header[PAYLOAD_SIZE_INDEX_FROM_CLIENT]
            payload = self.receive_payload(payload_size, header[OP_CODE_INDEX_FROM_CLIENT])
            packet_bytes = data+payload
            return self.req_select(header, payload, packet_bytes)
        except Exception as e:
            print(f'Server error: while receiving request from the client {e} ')  # handle it
            return b''

    def receive_payload(self, payload_size, code) -> bytes:
        """Receiving payload in chunks """
        if code != INIT_REGISTRATION_SUCCEEDED:
            payload_size += SIGNATURE_SIZE
        to_get = min(payload_size, constants.CHUNK_SIZE)
        size = payload_size
        payload = bytearray()
        try:
            while size > 0:
                data = self.client_socket.recv(to_get)
                payload.extend(data)
                size -= to_get
                to_get = min(size, constants.CHUNK_SIZE)
        except ConnectionResetError or OSError as e:
            raise e
        return payload

    def send_response(self, response,other_client_socket=None) -> bool:
        """Sends a response to the client via socket"""
        try:
            if other_client_socket is None:
                self.client_socket.sendall(response)
            else:  # Sends a packet to another client from a sending client
                other_client_socket.sendall(response)
            return True
        except socket.error as e:
            print(f'Could not send data {e}')
            return False

    # =========================== Response Handlers ===========================
    def req_select(self, header, payload, packet_bytes=b''):
        """
        Selects and handles the appropriate request based on the operation code (OP_CODE).
        This method processes an incoming request by first verifying the client's signature on the request
        If the signature is valid, it selects the corresponding handler method, otherwise it will send an error message
        """
        sender_id = header[SENDER_ID_INDEX_FROM_CLIENT]; code = header[OP_CODE_INDEX_FROM_CLIENT]
        verify_signature = self.crypto_handler.verify_sig_from_client(sender_id, packet_bytes, payload[-SIGNATURE_SIZE:], code=code)
        if not verify_signature:
            return self.unverified_signature_error(sender_id,code)
        request = self.request_dict[code]
        return request(header, payload,packet_bytes)

    def init_response(self, sender_id, recipient_id, op_code, payload, timestamp=None, version=VERSION):
        """
        Initializes a response packet by packing the version, sender/recipient IDs,
        operation code, payload size, and payload.
        Then it signs all the packed data, and sends it all together to the client
        """
        payload_size = len(payload)
        fmt = f'<B I I 19s B H {payload_size}s'
        timestamp = self.get_timestamp(timestamp)
        # Pack the message
        packed_data = struct.pack(fmt, version, sender_id, recipient_id, timestamp, op_code, payload_size, payload)
        packed_data += self.crypto_handler.sign_server_packet(packed_data, op_code, None)
        return packed_data

    def register_new_client(self, header, payload, packet_bytes=b''):
        """
         Handles client request 100,register as a new client to this server.
         Decrypts client's phone number with the server's private key and sends an OTP in a secured channel
         If the client is already registered, an error message will be sent
        """
        try:
            phone_num_bytes = self.crypto_handler.decrypt_clients_payload_asym(payload)
            phone_num = struct.unpack('<I', phone_num_bytes)[0]
            if not self.database.find_username(phone_num):
                return self.SendBySecureChannel(phone_num)
            else:
                return self.init_response(SERVER_ID,phone_num,CLIENT_IS_REGISTERED,b'')
        except Exception as e:
            return self.init_response(SERVER_ID,INITIAL_ID,GENERAL_ERROR,b'')

    def SendBySecureChannel(self,phone_num):
        """Sends an OTP in a secured channel"""
        secured_channel_payload = self.generate_OTP(phone_num)
        return self.init_response(SERVER_ID, phone_num, INIT_REGISTRATION_SUCCEEDED, secured_channel_payload)

    def verify_initial_registration(self, header, payload,packet_bytes):
        """
        Handles request code 101, verifies the initial registration of a client.
        This function handles the verification process during the initial client registration:
        It checks the client's provided signature using their public key.
        Decrypts the One-Time Password (OTP) from the encrypted payload and verifies it.
        If OTP verification succeeds, it adds the client to the database,
        associates their public key with their user ID, and generates an AES key for encrypted communication.
        """
        try:

            client_public_key = payload[RSA_KEY_SIZE:-SIGNATURE_SIZE]
            signature = payload[-SIGNATURE_SIZE:]; uid = header[0]
            self.crypto_handler.verify_sig_from_client(uid, packet_bytes, signature, client_public_key, S_PUBLIC_KEY)
            encrypted_otp = payload[:RSA_KEY_SIZE]
            decrypted_payload = self.crypto_handler.decrypt_clients_payload_asym(encrypted_otp)
            otp = decrypted_payload.decode()

            if self.authenticate_otp(otp, uid):
                self.add_new_client_to_db(uid)
                self.database.update_entry(CLIENTS_TABLE, uid, PUBLIC_KEY_FIELD,client_public_key)
                self.connected_clients[uid] = self.client_socket
                encrypted_aes = self.crypto_handler.generate_aes_key(uid, client_public_key)
                print(f'Client\'s {uid} OTP was verified successfully\n')
                return self.init_response(SERVER_ID, uid, VERIFIED_OTP_PUBLIC_KEY, encrypted_aes)
            else:
                print(f'Server error: Could not verify initial registration for client {uid}')
                return self.general_error(INITIAL_ID,b'')
        except Exception as e:
            raise e

    def authenticate_otp(self, otp, user_id):
        """"Checks if the otp from the client is matching and is not expired (5 minutes)"""
        if otp not in self.OTP:
            return False
        expiration_time, uid = self.OTP[otp]
        if datetime.now()-expiration_time <= timedelta(minutes=5) and uid == user_id:
            print('OTP was verified successfully')
            self.OTP.pop(otp)
            return True
        else:
            print(f'Client\'s {user_id} OTP could not be verified')
        return False

    def generate_OTP(self,user_id):
        """
        Generates a new OTP for a user
        It is mapped with to a tuple with the time of creation and user_id
        """
        self.clear_expired_OTP()
        one_time_password = random.randint(MIN_OTP_VAL,MAX_OTP_VAL)
        while one_time_password in self.OTP.keys():
            one_time_password = random.randint(MIN_OTP_VAL, MAX_OTP_VAL)
        self.OTP[str(one_time_password)] = (datetime.now(),user_id)
        return str(one_time_password).encode('utf-8')

    def clear_expired_OTP(self):
        """Clears any allocated OTPs that were created more than 5 minutes ago """
        keys = self.OTP.keys()
        for key in keys:
            if (datetime.now() - self.OTP[key][0]) >= timedelta(minutes=5):
                self.OTP.pop(key)

    def send_clients_public_key(self, header,payload,packed_bytes):
        """
        Handles request code 105, a request from a client to retrieve the public key of another client.
        It decrypts the request using AES encryption, retrieves the requested client's public key from the database,
        encrypts the public key with the requesting client's AES key,
        and returns the encrypted public key as part of the response.
        """
        try:
            sender_id = header[0]
            print(f'Server is handling public key request from client {sender_id}')
            aes_key = self.database.get_data(CLIENTS_TABLE, sender_id, AES_KEY_FIELD)
            decrypted_payload = aes_decryption(aes_key,payload[:IV_LEN], payload[IV_LEN:IV_LEN+IV_LEN])
            recipient_id = int(decrypted_payload.decode())
            recipient_public_key = self.database.get_data(CLIENTS_TABLE,recipient_id,PUBLIC_KEY_FIELD)
            sender_aes_key = self.database.get_data(CLIENTS_TABLE, sender_id,AES_KEY_FIELD)
            enc_recipient_public_key, iv = aes_encryption(recipient_public_key, sender_aes_key)
            payload = iv+enc_recipient_public_key
            return self.init_response(constants.SERVER_ID, sender_id, SEND_CLIENT_PUB_KEY, payload)
        except Exception as e:
            return self.general_error(header[0], b'Could not complete request 105, possibly unregistered client')
    def deliver_message_to_other_client(self, header, payload, packet_bytes):
        """
        Handles request code 102, delivers a message from one client to another and sends a confirmation to the sender.
        This function retrieves the recipient's ID and sender's ID from the header, checks if the recipient
        is connected or not; either sends the message or stores it for delivery upon it's reconnecting.
        Then sends a confirmation message back to the sender about the message status.
        """
        recipient_id = header[RECIPIENT_ID_INDEX_FROM_CLIENT]
        sender_id = header[SENDER_ID_INDEX_FROM_CLIENT]
        recipient_socket = self.get_connected_client(recipient_id)
        status = MESSAGE_PASSED
        if isinstance(recipient_socket, int):
            self.database.insert_message(recipient_id,packet_bytes)
            status = CLIENT_DISCONNECTED
        else:
            self.send_response(struct.pack('< B', VERSION)+packet_bytes, recipient_socket)
        return self.message_sent_confirmation(sender_id, recipient_id, status)

    def message_sent_confirmation(self,uid,recipient_id, status):
        """
        Sends a confirmation message to the sender regarding the status of a message sent to a recipient.
        """
        try:
            aes_key = self.database.get_data(constants.CLIENTS_TABLE, uid, constants.AES_KEY_FIELD)
            message = self.get_confirmation_message_status(recipient_id, status)
            encrypted_payload, iv = aes_encryption(message[0].encode('utf-8'), aes_key)
            pay = iv+encrypted_payload
            return self.init_response(constants.SERVER_ID, uid, message[1], pay)
        except Exception as e:
            raise Exception(f'message_sent_confirmation {e}')

    def get_confirmation_message_status(self, recipient_id, status):
        """
        Returns the confirmation message and
        corresponding response code based on the status of the message delivery.
        """
        code = MESSAGE_DELIVERY_CONFIRMATION_TO_SENDER
        status_messages_dict = {
            MESSAGE_PASSED:(f'Message sent successfully to client {recipient_id}', code),
            NETWORK_ERROR:('Message Could not be sent due to network error', GENERAL_ERROR),
            CLIENT_NOT_EXIST:('Message Could not be sent to an unregistered client', GENERAL_ERROR),
            CLIENT_DISCONNECTED:('Client is not online, The server will deliver it when client\'s connection is restored', code)
        }
        return status_messages_dict[status]

    def add_new_client_to_db(self, name):
        """Adds a new client (phone number) to the DB"""
        self.database.add_new_client_db(name, name)
        print(f'Server: Client {name} was registered successfully')

    def make_request_dict(self):
        """Creates a dictionary mapping request types to their corresponding handler methods"""
        requests = {
            REGISTER: self.register_new_client,
            S_PUBLIC_KEY: self.verify_initial_registration,
            CLIENT_SEND_MSG_TO_CLIENT: self.deliver_message_to_other_client,
            GET_RECIPIENT_PUB_KEY: self.send_clients_public_key,
            CLIENT_RECONNECT_REQUEST: self.reconnection_request_from_client,
            DISCONNECT: self.disconnect_client,
        }
        return requests

    def disconnect_client(self, header, payload=b'', packet_bytes=b''):
        """Handles request 222, Client disconnection from the server"""
        try:
            client_id = header[SENDER_ID_INDEX_FROM_CLIENT]
            if self.remove_connected_client(client_id):
                return self.init_response(constants.SERVER_ID, client_id, DISCONNECT, b'')
        except Exception as e:
            raise e

    def unverified_signature_error(self,sender_id,code):
        """
        Handles an error when the server cannot verify the client's signature on a request.
        It generates an error message for the client about the signature verification
        failure and suspects a man-in-the-middle (MITM) attack.
        """
        print(f'Error! could not verify signature from client {sender_id} on request {code}')
        code_bytes = str(code).encode('utf-8')
        message = b'Server could not verify your signature on request ' + code_bytes + (b'. Suspected MITM!!!'
                                                                                     b'\nRequest was not executed.')
        aes_key = self.database.get_data(CLIENTS_TABLE, sender_id, AES_KEY_FIELD)
        encrypted_error_message, iv = aes_encryption(message, aes_key)
        message = iv + encrypted_error_message
        return self.init_response(SERVER_ID,sender_id,UNVERIFIED_SIGNATURE,sender_id,message)

    def reconnection_request_from_client(self,header,payload,packet_bytes):
        """
        Handles request code 106, reconnection request from a client, including verifying if the client is registered
        in the database, decrypting the client's payload, and initiating the AES key exchange.
        If the client is registered and the decrypted payload matches the sender's ID,
        the server establishes a connection with the client, processes any offline messages,
        and handles the AES exchange for secure communication.
        """
        try:
            sender_id = header[SENDER_ID_INDEX_FROM_CLIENT]
            decrypted_payload = self.crypto_handler.decrypt_clients_payload_asym(payload[:SIGNATURE_SIZE])
            is_registered = self.database.get_data(CLIENTS_TABLE, sender_id, sender_id)
            if is_registered is None:
                print(f"Error -> Client {sender_id} isn't registered!!")
            elif int(decrypted_payload) == sender_id:
                self.add_connected_client(sender_id)
                self.handle_aes_exchange_in_reconnection(sender_id)
                return self.deliver_offline_messages(sender_id)
        except Exception as e:
            raise Exception(f'Could not handle reconnection request from {header[SENDER_ID_INDEX_FROM_CLIENT]} {e}')

    def handle_aes_exchange_in_reconnection(self, sender_id):
        """
        Handles the AES key exchange during a client's reconnection process.
        It retrieves the client's public key from the database,
        generates a new AES key, and sends the encrypted AES key to the client.
        The method also includes the message count as part of the reconnection response.
        """
        try:
            client_public_key = self.database.get_data(CLIENTS_TABLE, sender_id, PUBLIC_KEY_FIELD)
            encrypted_aes = self.crypto_handler.generate_aes_key(sender_id, client_public_key)
            message_count = self.database.count_values(sender_id)
            reconnect = self.init_response(constants.SERVER_ID, sender_id, constants.CLIENT_RECONNECT_APP, encrypted_aes,
                                           version=message_count)
            self.send_response(reconnect)
        except Exception as e:
            raise Exception(f'During aes exchange in reconnection request for client {e}')

    def deliver_offline_messages(self, reconnected_id):
        """
        Delivers offline messages to a reconnected client.
        This method checks if the client with the given `reconnected_id` has any offline messages in the database.
        If there are messages, it sends each message to the client and then deletes it from the queue once successfully delivered.
        The method continues to send messages as long as the client is connected and has messages to deliver.
        """
        messages_count = self.database.count_values(reconnected_id)
        while self.connected_clients[reconnected_id] and self.database.count_values(reconnected_id) > 0:
            try:
                recipient_socket = self.connected_clients[reconnected_id]
                packet_to_send, packet_num = self.database.get_queued_message(reconnected_id)
                message_sent = self.send_response(struct.pack('< B', messages_count) + packet_to_send, recipient_socket)
                deleted = self.database.delete_queued_message(reconnected_id,packet_num)
                key_req = self.handle_req()
                self.send_response(key_req)
            except Exception as e:
                raise Exception(f'While sending offline messages to reconnected client {reconnected_id,e}')
        return self.init_response(SERVER_ID, reconnected_id, DONE_OFFLINE_MESSAGES, b'')

    def general_error(self, sender, message):
        payload = b''
        if message:
            aes_key = self.database.get_data(CLIENTS_TABLE,sender,AES_KEY_FIELD)
            payload,iv = aes_encryption(message,aes_key)
            payload = iv + payload
        return self.init_response(SERVER_ID, sender, GENERAL_ERROR, payload)
    # =========================== Utils ===========================

    def get_timestamp(self, timestamp):
        """Time stamp format fot the server's packet"""
        if timestamp is None:
            date = datetime.now()
            fmt_date = date.strftime('%Y-%m-%d %H:%M:%S')
        else:
            fmt_date = timestamp
        return fmt_date.encode('utf-8')

    def add_connected_client(self, uid):
        """Add a clients from the connected clients dictionary (connecting the client to the server)"""
        with self.lock:
            if uid in self.connected_clients:
                print('Client is already connected!')
            else:
                self.connected_clients[uid] = self.client_socket
                print(f'Client {uid} reconnected successfully')

    def remove_connected_client(self, uid):
        """Removes a clients from the connected clients dictionary (disconnecting the client from the server)"""
        with self.lock:
            if uid in self.connected_clients:
                del self.connected_clients[uid]
                print(f"Client {uid} disconnected from the server successfully.")
                return True
            else:
                raise Exception(f'Could not remove client {uid} during disconnection request')

    def get_connected_client(self, uid):
        """Gets a socket of a connected client"""
        with self.lock:
            if uid in self.connected_clients:
                #print(self.connected_clients[uid])
                return self.connected_clients[uid]
            else:
                client_uid = self.database.get_data(constants.CLIENTS_TABLE, uid, uid)
                if client_uid is None:
                    print('Client does not exist cant send msg')
                return client_uid



