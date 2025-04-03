from CryptoHandler import CryptoHandler
from ServerRequestHandler import RequestHandler
from ClientsDB import ClientsDB
import threading
import constants
import socket


class Server:
    """
    This module implements a server that handles client connections and manages secure communication
    using cryptographic protocols. It provides functionality to accept multiple client connections,
    handle client requests, and send responses, within a multithreaded environment.

    """
    def __init__(self):
        """ Constructor for Server class """
        self.database = ClientsDB()  # Clients and messages SQLite DB
        self.crypto_handler = CryptoHandler(self.database)  # Cryptographic operations module
        self.OTP = {}  # OTP mapped to creation time and associated user to control OTP verification
        self.connected_clients = {}  # User id mapped to a socket to manage active connections
    def start_server(self):
        """ Starts the server, binding it and start listening for incoming clients """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.server_socket:
            listening = self.set_connection()
            while True and listening:
                self.accept_client()

    def handle_client(self, client_socket):
        """
        This method initializes a `RequestHandler` instance to manage the client's requests and responses.
        It continuously processes incoming requests from the client socket and sends appropriate responses.
        The loop runs until the client disconnects or an error occur
        """
        request_handler = RequestHandler(client_socket, self.database, self.crypto_handler,self.OTP,self.connected_clients )
        try:
            while True:
                response = request_handler.handle_req()
                if not response:
                    break

                if response:
                    request_handler.send_response(response)
        except Exception as e:
            raise ValueError(f'Server error: While handling client {e}')
        finally:
            client_socket.close()

    def set_connection(self):
        """
        Binds the server socket to the host and port for listening
        Port data is on a file port.info, if this one does not exist
        The server will be connected to A protocol defined default port
        """
        try:
            self.server_socket.bind((constants.HOST, constants.DEFAULT_PORT))
            print(f'listening on {constants.HOST}:{constants.DEFAULT_PORT}\n############################')
            self.server_socket.listen(0)
            return True
        except Exception as e:
            if isinstance(e, OSError):
                print(f"Server error: While setting connection could not bind to {constants.HOST}:{constants.DEFAULT_PORT} - {e}")
            else:
                print(f"Server error: While setting connection {e}")
            return False

    def accept_client(self):
        """ Accepts a new client connection and starts a new thread to handle it """
        try:
            client_socket, addr = self.server_socket.accept()
            print(f'Client connected {str(addr)}')
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
        except Exception as e:
            print(f'Server Error: While accepting new client {e}')


def main():
    server = Server()
    server.start_server()


if __name__ == '__main__':
    main()
