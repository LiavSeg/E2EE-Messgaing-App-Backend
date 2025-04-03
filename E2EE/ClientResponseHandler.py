from CryptoHandler import *
from constants import *
import socket
import struct

class ClientRespHandler:
    def __init__(self, num, sock,client):
        self.phone_number = num
        self.aes_key = b''
        self.responses = self.make_response_dict()
        self._socket = sock
        self.client = client
        self.pending = False
    # =========================== Connection related ===========================
    def get_server_response(self):
        """
        Retrieves the server's response by reading the response header and payload from the socket.
        The method also retrieves the signature for the response, which is checked later.
        """
        try:
            bytes_response = b''
            header_bytes = self._socket.recv(SERVER_HEADER_SIZE)
            header = struct.unpack(CLIENT_UNP_HEADER_FMT, header_bytes)
            payload_bytes, payload_size = self.recieve_signature(header[OP_CODE_INDEX_FROM_SERVER],
                                                                 header[PAYLOAD_SIZE_INDEX_FROM_SERVER])
            payload = struct.unpack(f'!{payload_size}s', payload_bytes)
            response = header + payload
            bytes_response += (header_bytes + payload_bytes)
            print(f'\nClient recieved new a response from server: {header[OP_CODE_INDEX_FROM_SERVER]}')
            return response, bytes_response
        except Exception as e:
            print(f'Client error: While getting server\'s response {e}')

    def recieve_signature(self, code, payload_size):
        payload_bytes = self._socket.recv(payload_size)
        if code != INIT_REGISTRATION_SUCCEEDED:
            payload_bytes += self._socket.recv(SIGNATURE_SIZE)
            payload_size += SIGNATURE_SIZE
        return payload_bytes, payload_size

    # =========================== Response Handlers ===========================
    def make_response_dict(self):
        """Creates a dictionary mapping response types to their corresponding handler methods"""
        responses = {
            VERIFIED_OTP_PUBLIC_KEY: self.get_aes,
            CLIENT_SEND_MSG_TO_CLIENT: self.recieve_message_from_other_client,
            MESSAGE_DELIVERY_CONFIRMATION_TO_SENDER: self.recieve_message_status,
            SEND_CLIENT_PUB_KEY: self.handle_recipient_public_key,
            CLIENT_RECONNECT_APP: self.handle_reconnection_response,
            DONE_OFFLINE_MESSAGES: self.done_messages,
            DISCONNECT: self.disconnect,
            CLIENT_IS_REGISTERED: self.handle_error_from_server,
            UNVERIFIED_SIGNATURE: self.handle_error_from_server,
            GENERAL_ERROR: self.handle_error_from_server
        }
        return responses

    def handle_server_response(self):
        """
        Handles the server's response by verifying the signature and processing the response based on the operation code
        """
        response, bytes_response = self.get_server_response()
        code = response[OP_CODE_INDEX_FROM_SERVER]
        if not self.validate_server_sig(bytes_response, code):
            print(f'Could not verify Signature of response: {code}')
            return
        if code == INIT_REGISTRATION_SUCCEEDED:  # response 200, was sent in secured channel
            return response
        else:
            f = self.responses[code]
            return f(response,bytes_response)

    def get_aes(self, response, packed_data):
        """
        Handles response code 201, AES key exchange from the server
        The key is encrypted with the client's public RSA key
        This AES key will be used by the server and client to communicate during this session
        """
        try:
            enc_aes = response[PAYLOAD_INDEX_FROM_SERVER][:SIGNATURE_SIZE]
            decrypted_aes = client_decrypt_asymmetric(self.phone_number, enc_aes)
            self.aes_key = decrypted_aes
            return self.aes_key
        except Exception as e:
            print(f'Error while getting aes key {e}')
            return False

    def recieve_message_from_other_client(self, response, packet_bytes):
        """
        Handles response code 102 from the server, a new message has been received from another client.
        It decodes the sender's ID,asks from the sever for the sender's public key,
        verifies the signature of the message, decrypts the message using RSA encryption,
        and formats the message for output.
        """
        try:
            encoded_client_num = self.client.encode_client_number(response[SENDER_ID_INDEX_FROM_SERVER])
            self.client.send_message(GET_RECIPIENT_PUB_KEY,encoded_client_num)
            sender_public_key = self.is_self_message(response)
            verify_sig(sender_public_key, packet_bytes[SENDER_ID_INDEX_FROM_SERVER:-SIGNATURE_SIZE],
                       response[PAYLOAD_INDEX_FROM_SERVER][SIGNATURE_SIZE:], True)
            msg_recieved = client_decrypt_asymmetric(self.phone_number, response[PAYLOAD_INDEX_FROM_SERVER][:SIGNATURE_SIZE])
            formated_output = self.format_message_from_client(response, msg_recieved)
            print(formated_output)
        except Exception as e:
            print(f'While receiving a message {e} ')
            return False

    def recieve_message_status(self, response,packed_data):
        """
        Handles response code 203, a status message from the server regarding a message the client sent
        cases: an error/message delivered online/ message delivered offline
        """
        payload = response[PAYLOAD_INDEX_FROM_SERVER]
        iv = payload[:IV_LEN]
        enc = payload[IV_LEN:-SIGNATURE_SIZE]
        decrypted_payload = aes_decryption(self.aes_key, enc, iv)
        if decrypted_payload is None:
            print('decrypted_payload- is none System detected a possible security issue, this message is invalid')
            return False
        else:
            print(f'\033[32m***\033[0m {decrypted_payload.decode()} \033[32m***\033[0m')
        return True


    def handle_recipient_public_key(self, response,packet_bytes):
        """ Handles response code 204, receiving a client's public RSA key """
        payload = response[PAYLOAD_INDEX_FROM_SERVER]
        iv, enc = payload[:KEY_START], payload[KEY_START:KEY_END]
        recipient_public_key = aes_decryption(self.aes_key, enc, iv)
        return recipient_public_key

    def handle_reconnection_response(self, response, bytes_response):
        """
        Handles response code 206, reconnection request to the server
        It receives number of awaiting messages and encrypted AES key, decrypts it and saves it locally for the current session
        returns the aes key and number of messages for further handling
        """
        aes = self.get_aes(response, bytes_response)
        print(f'Client {self.phone_number} reconnected successfully\nChecking for new messages\n')
        new_messages_count = response[0]
        return aes, new_messages_count

    def get_offline_messages(self, num_of_messages,aes):
        """Receiving all messages that were sent to the client while offline from the server """
        print(f'There are {num_of_messages} new messages')
        self.pending = True if num_of_messages>0 else False
        while num_of_messages >= 0:
            try:
                self.handle_server_response()
                num_of_messages -= 1
            except Exception as e:
                print(e)
                return False
        return True

    def disconnect(self,response,packet_bytes):
        """Handles repose code 222, disconnection approval from the server"""
        return DISCONNECT
    def done_messages(self,response,packet_bytes):
        """Handles repose code 255, all offline messages were sent"""
        if not self.pending:
            print('You dont have any pending messages')
        else:
            print('All pending messages recieved!')
            self.pending = False

    def validate_server_sig(self, response, code):
        """Validates the server's signature on the response packet to ensure its integrity and authenticity."""
        if code in VERIFY_LATER:  # responses: 200 secured channel, 102 will be verified with the sender's key later
            return True
        try:
            print(f'\tChecking the server\'s signature on the packet for response: {code}')
            server_public_key = get_server_public_key()
            signature = response[-SIGNATURE_SIZE:]
            verify_sig(server_public_key, response[:-SIGNATURE_SIZE], signature)
            print(f'\tServer\'s signature was verified for response: {code}\n')
            return True
        except Exception as e:
            print(f'\tWhile validating server\'s signature {code, e}')
            return False


    def is_self_message(self, response):
        """
        Handles the case where client sends a message to himself in response 102:
        gets the message confirmation and then the public key from the server
        otherwise the client gets the public key of the sender right away
        """
        sender_id = response[SENDER_ID_INDEX_FROM_SERVER]
        recipient_id = response[RECIPIENT_ID_INDEX_FROM_SERVER]
        if sender_id == recipient_id:
            self.handle_server_response()
        key = self.handle_server_response()
        return key

    def format_message_from_client(self, response, message_recieved):
        """Formats the message recieved from another client"""
        try:
            sender_id = response[SENDER_ID_INDEX_FROM_SERVER]
            timestamp = response[TIMESTAMP_INDEX_FROM_SERVER].decode()
            decoded_message = message_recieved.decode()
            return (f'\n{GREEN_TEXT_ST}*************************{COLOR_END}\nNew message recieved:\n\t'
                    f'From: {sender_id}\n\t'
                    f'To: {self.phone_number}\n\t'
                    f'Content: {GREEN_BACKG_ST}{decoded_message}{COLOR_END}\n\t'
                    f'Time: {timestamp}\n'
                    f'{GREEN_TEXT_ST}*************************{COLOR_END}')
        except Exception as e:
            raise e



    def handle_error_from_server(self, response, packet_bytes):
        """
        Handles errors received from the server, based on the error code in the response.
        This function processes server error responses by checking the error code and taking appropriate actions.
        Client is already registered or when there is an unverified signature in the server response.
        """
        error_code = response[OP_CODE_INDEX_FROM_SERVER]
        if error_code == CLIENT_IS_REGISTERED:
            print(f'{RED_START}You are already registered!\nPlease reconnect properly.{COLOR_END}')
            return False
        elif error_code == UNVERIFIED_SIGNATURE:
            return self.unverified_sig(response[PAYLOAD_INDEX_FROM_SERVER])
        else:
            return self.general_error(response[PAYLOAD_INDEX_FROM_SERVER])
    def unverified_sig(self,response):
        """Receiving an error report regarding failed signature verification """
        message = aes_decryption(self.aes_key, response[IV_LEN:-SIGNATURE_SIZE], response[:IV_LEN])
        print(message)
        return False

    def general_error(self, response):
        """Receiving a general error report from the server """
        if not response:
            print('Server responded with an error on request: 100')
            return False
        else:
            message = aes_decryption(self.aes_key, response[IV_LEN:-SIGNATURE_SIZE], response[:IV_LEN]).decode()
            print(f'\033[31mServer responded with an error: {message}\033[0m')
            return False

