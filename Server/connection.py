import socket
import selectors

from protocol import Request, Response
from crypto import AESWrapper
from file_handler import FileHandler


PACKET_SIZE = 32768  # 32KB


class Connection:
    """
    The Connection class manages a socket connection to a server.

    Attributes:
        sock (socket): The socket object for the connection.
        addr (tuple): The address of the connected client (IP, port).
        selector (selectors): The selector for managing I/O events.
        _send_buffer (bytes): Buffer for outgoing data.
        is_closed (bool): Flag indicating if the connection is closed.
        aes_wrapper (AESWrapper): Instance of AESWrapper for encryption/decryption.
        file_handler (FileHandler): Instance of FileHandler for managing file operations.
        request (Request): Placeholder for the request to be sent or received.
        response (Response): Placeholder for the response to be sent or received.
        got_file (bool): Flag indicating if the next packets are part of a file transfer.
        errors_num (int): Counter for the number of errors encountered.

    Args:
        sock (socket.socket): The socket object representing the connection.
        addr (tuple): The address of the connected client (IP, port).
        selector (selectors.DefaultSelector): The selector for managing I/O events.
    """
    def __init__(self, sock: socket.socket, addr: tuple, selector: selectors.DefaultSelector):
        self.sock = sock
        self.addr = addr
        self.selector = selector
        self._send_buffer = b''
        self.is_closed = False
        self.aes_wrapper = AESWrapper()
        self.file_handler = FileHandler()
        self.request = None
        self.response = None
        self.got_file = False  # a flag to know if the next packets are supposed to be only a file's payload.
        self.errors_num = 0

        # Register for read events initially
        self.selector.register(self.sock, selectors.EVENT_READ, data=self)

    def read(self) -> bytes:
        """Read data from the socket and return it."""
        try:
            data = self.sock.recv(PACKET_SIZE)
            if data:
                return data
            else:
                self.close()  # Connection closed by the client
                return b''
        except IOError as e:
            print(f"Error reading from {self.addr}: {e}")
            self.close()
            return b''

    def write(self):
        """Write data from the send buffer to the socket."""
        if self._send_buffer:
            try:
                sent = self.sock.send(self._send_buffer)
                self._send_buffer = self._send_buffer[sent:]
                if len(self._send_buffer) == 0:
                    # Switch back to read mode if all data is sent
                    self.selector.modify(self.sock, selectors.EVENT_READ, data=self)
            except IOError as e:
                print(f"Error writing to {self.addr}: {e}")
                self.close()

    def queue_data(self, data: bytes):
        """Queue data to be sent and register for write events."""
        self._send_buffer += data
        self.selector.modify(self.sock, selectors.EVENT_WRITE, data=self)

    def close(self):
        """Close the connection and unregister from the selector."""
        if not self.is_closed:
            print(f"Closing connection to {self.addr}")
            self.selector.unregister(self.sock)
            self.sock.close()
            self.is_closed = True
