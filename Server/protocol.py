import struct
from enum import IntEnum
from typing import Union

# Define constants
SERVER_VERSION = 3

VERSION_SIZE = 1
CODE_SIZE = 2
PAYLOAD_SIZE = 4
CLIENT_ID_SIZE = 16
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
FILE_NAME_SIZE = 255
CONTENT_SIZE = 4
ORIGINAL_FILE_SIZE = 4
PACKET_NUMBER_SIZE = 2
TOTAL_PACKET_SIZE = 2
CRC_SIZE = 4


# Enum for Request and Response Codes
class RequestCode(IntEnum):
    REQUEST_REGISTER = 825
    REQUEST_PUBLIC_KEY = 826
    REQUEST_LOGIN = 827
    REQUEST_SEND_FILE = 828

    REQUEST_CRC_VALID = 900
    REQUEST_CRC_INVALID = 901
    REQUEST_CRC_FATAL = 902


class ResponseCode(IntEnum):
    RESPONSE_REGISTRATION = 1600
    RESPONSE_REGISTRATION_FAILED = 1601
    RESPONSE_AES_KEY = 1602
    RESPONSE_FILE_VALID = 1603
    RESPONSE_ACK = 1604
    RESPONSE_LOGIN = 1605
    RESPONSE_LOGIN_FAILED = 1606
    RESPONSE_ERROR = 1607


# Define payload structures (this should match the C++ payloads)
class NameRequest:
    """ A payload that contains the name of the client """
    def __init__(self, name: str):
        self.name = name


class SendPublicKeyRequest:
    """ The public key request payload """
    def __init__(self, name: str, public_key: bytes):
        self.name = name
        self.public_key = public_key


class SendFileRequest:
    """ The structure of the file request payload """
    def __init__(self
                 , content_size: int
                 , original_file_size: int
                 , current_packet: int
                 , total_packets: int
                 , file_name: str
                 , content: bytes):
        self.content_size = content_size
        self.original_file_size = original_file_size
        self.current_packet = current_packet
        self.total_packets = total_packets
        self.file_name = file_name
        self.content = content


class CRCRequest:
    """ A payload that contains the file name """
    def __init__(self, file_name: str):
        self.file_name = file_name


class ClientIDResponse:
    """ A payload that contains the client ID. """
    def __init__(self, client_id: bytes):
        self.client_id = client_id


class SymmetricKeyResponse:
    """ The structure of the symmetric key response"""
    def __init__(self, client_id: bytes, symmetric_key: bytes):
        self.client_id = client_id
        self.symmetric_key = symmetric_key


class FileResponse:
    """ The structure of the file response payload to be sent to the client """
    def __init__(self, client_id: bytes, content_size: int, file_name: str, crc: int):
        self.client_id = client_id
        self.content_size = content_size
        self.file_name = file_name
        self.crc = crc


class ErrorResponse:
    pass


# Union type for Payload
Payload = Union[
    NameRequest
    , SendPublicKeyRequest
    , SendFileRequest
    , CRCRequest
    , ClientIDResponse
    , SymmetricKeyResponse
    , FileResponse
    , ErrorResponse]


# Request structure
class Request:
    """
    The Request class is used to encode and decode request data.

    Attributes:
        client_id (bytes): The client ID.
        version (int): The version of the request.
        opcode (int): The operation code of the request.
        payload (Payload): The dynamic payload of the request.
    """
    def __init__(self, client_id: bytes, version: int, opcode: RequestCode, payload_size: int, payload: Payload):
        self.client_id = client_id
        self.version = version
        self.opcode = opcode
        self.payload_size = payload_size
        self.payload = payload

    @staticmethod
    def deserialize(data: bytes):
        """ Deserialize bytes into a Request object """
        header_size = CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE
        client_id, version, opcode, payload_size = struct.unpack(f'<{CLIENT_ID_SIZE}sBHI', data[:header_size])
        try:
            code = RequestCode(opcode)
        except ValueError:
            raise ValueError(f'Invalid operation code: {opcode}')

        payload_data = data[header_size:]
        payload = Request.deserialize_payload(payload_data, code)
        expected_payload_size = Request.check_payload_size(payload)
        if payload_size != expected_payload_size:
            raise ValueError(f'Invalid payload size, expected: {expected_payload_size}, got: {len(payload_data)}')

        return Request(client_id, version, code, payload_size, payload)

    @staticmethod
    def deserialize_payload(payload_data: bytes, opcode: RequestCode) -> Payload:
        """ Deserialize bytes into a Request object """
        if opcode == RequestCode.REQUEST_REGISTER or opcode == RequestCode.REQUEST_LOGIN:
            name = struct.unpack(f'<{NAME_SIZE}s', payload_data)[0]
            name = name.decode('utf-8').rstrip('\0')
            return NameRequest(name)

        elif opcode == RequestCode.REQUEST_PUBLIC_KEY:
            name, public_key = struct.unpack(f'<{NAME_SIZE}s{PUBLIC_KEY_SIZE}s', payload_data)
            name = name.decode('utf-8').rstrip('\0')
            return SendPublicKeyRequest(name, public_key)

        elif opcode == RequestCode.REQUEST_SEND_FILE:
            payload_header_size = (CONTENT_SIZE +
                                   ORIGINAL_FILE_SIZE +
                                   PACKET_NUMBER_SIZE +
                                   TOTAL_PACKET_SIZE +
                                   FILE_NAME_SIZE)

            content_size, original_file_size, current_packet, total_packets, file_name = struct.unpack(
                f'<IIHH{FILE_NAME_SIZE}s'
                , payload_data[:payload_header_size]
            )
            file_name = file_name.decode('utf-8').rstrip('\0')
            content = payload_data[payload_header_size:]
            return SendFileRequest(content_size, original_file_size, current_packet, total_packets, file_name, content)

        elif (opcode == RequestCode.REQUEST_CRC_VALID
              or opcode == RequestCode.REQUEST_CRC_INVALID
              or opcode == RequestCode.REQUEST_CRC_FATAL):

            file_name = struct.unpack(f'<{FILE_NAME_SIZE}s', payload_data)[0]
            file_name = file_name.decode('utf-8').rstrip('\0')
            return CRCRequest(file_name)

        else:
            raise ValueError("Unknown opcode")

    @staticmethod
    def check_payload_size(payload: Payload) -> int:
        """ Returns the supposed payload size """
        if isinstance(payload, NameRequest):
            return NAME_SIZE
        elif isinstance(payload, SendPublicKeyRequest):
            return NAME_SIZE + PUBLIC_KEY_SIZE
        elif isinstance(payload, SendFileRequest):
            return (CONTENT_SIZE +
                    ORIGINAL_FILE_SIZE +
                    PACKET_NUMBER_SIZE +
                    TOTAL_PACKET_SIZE +
                    FILE_NAME_SIZE +
                    payload.content_size)
        elif isinstance(payload, CRCRequest):
            return FILE_NAME_SIZE
        else:
            raise ValueError("Unknown opcode")


# Response structure
class Response:
    """
    The Response class is used to encode and decode response data.

    Attributes:
        version (int): The version of the response.
        opcode (int): The operation code of the response.
        payload (Payload): The dynamic payload of the response.
        payload_size (int): The size of the payload.
    """
    def __init__(self, version: int, opcode: ResponseCode, payload: Payload):
        self.version = version
        self.opcode = opcode
        self.payload = payload
        self.payload_size = self.check_payload_size()

    def check_payload_size(self) -> int:
        """ Check the payload size """
        if isinstance(self.payload, ClientIDResponse):
            return CLIENT_ID_SIZE

        elif isinstance(self.payload, SymmetricKeyResponse):
            return CLIENT_ID_SIZE + len(self.payload.symmetric_key)

        elif isinstance(self.payload, FileResponse):
            return CLIENT_ID_SIZE + CONTENT_SIZE + FILE_NAME_SIZE + CRC_SIZE

        elif isinstance(self.payload, ErrorResponse):
            return 0

        else:
            raise ValueError("Unknown opcode")

    def serialize(self) -> bytes:
        """ Serialize the response """
        payload_data = self.serialize_payload()
        if len(payload_data) != self.payload_size:
            raise ValueError(f'Invalid payload size in register response, got: {len(payload_data)} '
                             f'needed {self.payload_size}')
        header = struct.pack(f'<BHI',
                             self.version,
                             self.opcode,
                             self.payload_size
                             )
        return header + payload_data

    def serialize_payload(self) -> bytes:
        """ Serialize the payload """
        if isinstance(self.payload, ClientIDResponse):
            return self.payload.client_id

        elif isinstance(self.payload, SymmetricKeyResponse):
            return self.payload.client_id + self.payload.symmetric_key

        elif isinstance(self.payload, FileResponse):
            file_name = self.payload.file_name.ljust(FILE_NAME_SIZE, '\0').encode('utf-8')
            return self.payload.client_id + struct.pack(
                f'<I{FILE_NAME_SIZE}sI',
                self.payload.content_size,
                file_name,
                self.payload.crc
            )

        elif isinstance(self.payload, ErrorResponse):
            return b''

        else:
            raise ValueError("Unknown payload type")
