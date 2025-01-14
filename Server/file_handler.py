import os
import cksum


BACKUP_PATH = os.path.join(os.getcwd(), 'backup')


class FileHandler:
    """
    A class to handle the file being received from the client.

    Attributes:
        file_name (str): The name of the file being received.
        file_path (str): The path of the file being received.
        tmp_file (str): A temporary file that will be deleted after the file has been saved.
        file_size (int): The size of the file being received.
        expected_packets (int): The total number of packets to be received from the client.
        packets (int): How many packets were received so far.
        encrypted_file_size (int): The size of the encrypted file.
    """
    def __init__(self):
        self.file_name = ''
        self.file_path = ''
        self.tmp_file = ''
        self.file_size = 0
        self.expected_packets = 0
        self.packets = 0
        self.encrypted_file_size = 0

        self.create_backup_folder()

    def set_file_name(self, file_name: str):
        """ Sets the name of the file being received."""
        self.file_name = file_name
        self.file_path = os.path.join(BACKUP_PATH, self.file_name)
        pos = file_name.find('.')
        if pos == -1:
            raise ValueError('Invalid file name')
        tmp_file_name = file_name[:pos] + '.bin'
        self.tmp_file = os.path.join(BACKUP_PATH, f'{tmp_file_name}')

    def set_file_size(self, file_size: int):
        """ Sets the size of the file being received."""
        self.file_size = file_size

    def set_expected_packets(self, expected_packets: int):
        """ Sets the total number of packets to be received from the client."""
        self.expected_packets = expected_packets

    def check_file_size(self) -> int:
        """ Returns the size of the file that was received."""
        return os.path.getsize(self.file_path)

    def delete_file(self):
        """ Deletes the file being received."""
        os.remove(self.file_path)

    def file_exists(self):
        """ Checks if the file being received exists."""
        return os.path.exists(self.file_path)

    def append_file_content(self, content: bytes, encrypted_content_size: int):
        """ Appends the content to the temporary file of the file being received."""
        self.packets += 1
        self.encrypted_file_size += encrypted_content_size
        with open(self.tmp_file, 'ab') as f:
            f.write(content)

    def create_file(self, data: bytes):
        """ Creates a file from the given data, and removes the temporary file."""
        os.remove(self.tmp_file)
        with open(self.file_path, 'wb') as f:
            f.write(data)

    def create_backup_folder(self):
        """ Creates the backup folder."""
        if not os.path.exists(BACKUP_PATH):
            os.makedirs(BACKUP_PATH)

    def get_content_from_file(self) -> bytes:
        """ Returns the content of the file being received."""
        with open(self.tmp_file, 'rb') as file:
            return file.read()

    def reset(self):
        """ Resets the class and deletes the temporary file."""
        if os.path.exists(self.tmp_file):
            os.remove(self.tmp_file)
        self.__init__()

    def get_crc(self) -> int:
        """ Returns the crc of the file being received."""
        return cksum.readfile(self.file_path)
