import socket
import selectors
import uuid
from connection import Connection
from database import Database
from protocol import *


SERVER_PORT_FILE = 'port.info'
DEFAULT_PORT = 1256
MAX_ERRORS = 3


class Server:
    """
    The Server class is responsible for handling multiple clients and applying the protocol on the requests
    and the responses.

    Attributes:
        host (str): The host address of the server.
        port (int): The port of the server.
        selector (selectors.DefaultSelector): A selector object that allows selecting clients.
        database (Database): A Database object that allows accessing databases.
        connections (Dictionary): A Dictionary of connections.

    Args:
        host (str): The host address of the server.
        port (int): The port of the server, the default is DEFAULT_PORT.
    """
    def __init__(self, host, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.selector = selectors.DefaultSelector()
        self.database = Database()
        self.connections = {}

    def start(self):
        """Start the server."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((self.host, self.port))
        server_sock.listen()
        print(f'Listening on {self.host}:{self.port}')
        server_sock.setblocking(False)

        # Register the server socket for read events
        self.selector.register(server_sock, selectors.EVENT_READ, data=None)

        try:
            self.run_event_loop()
        except KeyboardInterrupt:
            print('Shutting down...')
        finally:
            self.selector.close()

    def run_event_loop(self):
        """Run the main event loop for handling client connections."""
        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    # If the event is on the server socket, accept a new connection
                    self.accept_connection(key.fileobj)
                else:
                    # If the event is on a client connection, handle the data
                    connection = key.data
                    if mask & selectors.EVENT_READ:
                        self.handle_read(connection)
                    if mask & selectors.EVENT_WRITE:
                        self.handle_write(connection)

    def accept_connection(self, server_sock: socket.socket):
        """Accept a new client connection."""
        conn, addr = server_sock.accept()
        print(f"Accepted connection from {addr}")
        conn.setblocking(False)

        # Create a Connection instance and store it in the dictionary
        connection = Connection(conn, addr, self.selector)
        self.connections[conn] = connection

    def handle_read(self, connection: Connection):
        """Read data from the connection, deserialize, and process."""
        data = connection.read()
        if data:
            if not connection.got_file:     # not supposed to get file packets
                try:
                    connection.request = Request.deserialize(data)
                    if self.handle_request(connection):
                        response_bytes = connection.response.serialize()
                        connection.errors_num = 0
                        connection.queue_data(response_bytes)
                except Exception as e:
                    print(e)
                    connection.errors_num += 1
                    connection.queue_data(
                        Response(SERVER_VERSION, ResponseCode.RESPONSE_ERROR, ErrorResponse()).serialize()
                    )
                    if connection.errors_num >= MAX_ERRORS:
                        self.connections.pop(connection.sock)
                        connection.close()

            # receive the following file packets
            else:
                try:
                    self.handle_file_payload(connection, data)  #
                except Exception as e:
                    print(e)
                    connection.errors_num += 1
                    connection.queue_data(
                        Response(SERVER_VERSION, ResponseCode.RESPONSE_ERROR, ErrorResponse()).serialize()
                    )
                    if connection.errors_num >= MAX_ERRORS:
                        self.connections.pop(connection.sock)
                        connection.close()

    def handle_write(self, connection):
        """Send any queued data in the connection's buffer."""
        connection.write()

    def handle_request(self, connection) -> bool:
        """Handle the incoming request and generate a response."""
        opcode = connection.request.opcode

        if opcode == RequestCode.REQUEST_REGISTER:
            username = connection.request.payload.name
            if self.database.add_client(username):  # added client
                client_id = uuid.uuid4().bytes
                self.database.update_client_id(client_id, username)
                payload = ClientIDResponse(client_id)
                connection.response = Response(
                    SERVER_VERSION,
                    ResponseCode.RESPONSE_REGISTRATION,
                    payload
                )
            else:   # client already exists.
                payload = ErrorResponse()
                connection.response = Response(
                    SERVER_VERSION,
                    ResponseCode.RESPONSE_REGISTRATION_FAILED,
                    payload
                )
            return True

        elif opcode == RequestCode.REQUEST_LOGIN:
            client_id = connection.request.client_id
            username = connection.request.payload.name
            if self.database.check_login(client_id, username):     # check if name and public key exists.
                try:
                    self.database.update_last_seen(client_id)
                    self.database.update_aes_key(client_id, username, connection.aes_wrapper.get_aes_key())

                    public_key = self.database.get_public_key(client_id)
                    encrypted_aes_key = connection.aes_wrapper.encrypt_aes_with_rsa(public_key)

                    payload = SymmetricKeyResponse(client_id, encrypted_aes_key)
                    connection.response = Response(
                        SERVER_VERSION,
                        ResponseCode.RESPONSE_LOGIN,
                        payload
                    )
                except Exception as e:     # problem with the database
                    print(e)
                    payload = ClientIDResponse(client_id)
                    connection.response = Response(
                        SERVER_VERSION,
                        ResponseCode.RESPONSE_LOGIN_FAILED,
                        payload
                    )
            else:   # error with login, register again.
                payload = ClientIDResponse(client_id)
                connection.response = Response(SERVER_VERSION, ResponseCode.RESPONSE_LOGIN_FAILED, payload)
            return True

        elif opcode == RequestCode.REQUEST_PUBLIC_KEY:
            client_id = connection.request.client_id
            username = connection.request.payload.name
            public_key = connection.request.payload.public_key
            try:
                self.database.update_last_seen(client_id)
                self.database.update_aes_key(client_id, username, connection.aes_wrapper.get_aes_key())
                encrypted_aes_key = connection.aes_wrapper.encrypt_aes_with_rsa(public_key)
                payload = SymmetricKeyResponse(client_id, encrypted_aes_key)
                connection.response = Response(
                    SERVER_VERSION,
                    ResponseCode.RESPONSE_AES_KEY,
                    payload
                )
                self.database.update_public_key(client_id, username, public_key)
            except Exception as e:
                print(e)
                connection.response = Response(SERVER_VERSION, ResponseCode.RESPONSE_ERROR, ErrorResponse())
            return True

        elif opcode == RequestCode.REQUEST_SEND_FILE:
            connection.file_handler.reset()     # got a new file
            print('Receiving file ...')
            content_size = connection.request.payload.content_size
            file_size = connection.request.payload.original_file_size
            filename = connection.request.payload.file_name
            total_packets = connection.request.payload.total_packets
            content = connection.request.payload.content

            connection.file_handler.set_file_name(filename)

            if connection.file_handler.file_exists():      # replace the previous file with the same name
                connection.file_handler.delete_file()

            connection.file_handler.set_file_size(file_size)
            connection.file_handler.set_expected_packets(total_packets)

            connection.file_handler.append_file_content(content, content_size)
            connection.got_file = True
            self.database.update_last_seen(connection.request.client_id)
            return False  # for not sending the response

        elif opcode == RequestCode.REQUEST_CRC_VALID:
            client_id = connection.request.client_id
            payload = ClientIDResponse(client_id)
            connection.response = Response(SERVER_VERSION, ResponseCode.RESPONSE_ACK, payload)
            self.database.verify_file(client_id, connection.file_handler.file_name, connection.file_handler.file_path)
            self.database.update_last_seen(client_id)
            return True

        # do nothing, the client will send the file request again.
        elif opcode == RequestCode.REQUEST_CRC_INVALID:
            self.database.update_last_seen(connection.request.client_id)
            return True

        elif opcode == RequestCode.REQUEST_CRC_FATAL:
            client_id = connection.request.client_id
            payload = ClientIDResponse(client_id)
            connection.response = Response(SERVER_VERSION, ResponseCode.RESPONSE_ACK, payload)
            self.database.update_last_seen(client_id)
            return True

    def handle_file_payload(self, connection: Connection, data: bytes):
        """Handle a file payload."""
        file_payload = Request.deserialize_payload(data, RequestCode.REQUEST_SEND_FILE)
        content = file_payload.content
        content_size = file_payload.content_size
        connection.file_handler.append_file_content(content, content_size)

        if connection.file_handler.expected_packets == connection.file_handler.packets:
            print(f'Received file: {connection.file_handler.file_name}')
            connection.got_file = False

            encrypted_data = connection.file_handler.get_content_from_file()
            decrypted_data = connection.aes_wrapper.decrypt(encrypted_data)
            connection.file_handler.create_file(decrypted_data)

            client_id = connection.request.client_id
            content_size = connection.file_handler.encrypted_file_size
            file_name = connection.file_handler.file_name
            crc = connection.file_handler.get_crc()

            file_path = connection.file_handler.file_path
            self.database.add_file(client_id, file_name, file_path)

            payload = FileResponse(client_id, content_size, file_name, crc)
            connection.response = Response(SERVER_VERSION, ResponseCode.RESPONSE_FILE_VALID, payload)
            response_bytes = connection.response.serialize()
            connection.queue_data(response_bytes)


def main():
    try:
        with open(SERVER_PORT_FILE, 'r') as f:  # get the information about the server's port.
            port = int(f.read())
        if 0 < port < 65536:
            server = Server('', port)
            server.start()
        else:
            raise ValueError(f'Invalid port number: {port}')

    except Exception as e:
        print(e)
        server = Server('')
        server.start()


if __name__ == '__main__':
    main()
