import sqlite3
from datetime import datetime


DATABASE_NAME = 'defensive.db'


class Database:
    """
    SQL Lite3 Database Class that contains the clients and their files that were sent.

    Attributes:
        connection (sqlite3.Connection): Connection to the database
    """
    def __init__(self):
        self.connection = sqlite3.connect(DATABASE_NAME)
        self.create_client_table()
        self.create_file_table()

    def create_client_table(self):
        """Create the client table if it doesn't already exist."""
        with self.connection:
            self.connection.execute('''
                CREATE TABLE IF NOT EXISTS CLIENT_TABLE (
                    ID BLOB PRIMARY KEY,
                    Name TEXT NOT NULL,
                    PublicKey BLOB,
                    LastSeen TEXT,
                    AES_Key BLOB
                )
            ''')

    def create_file_table(self):
        """Create the file table if it doesn't already exist."""
        with self.connection:
            self.connection.execute('''
                CREATE TABLE IF NOT EXISTS FILE_TABLE (
                ID BLOB NOT NULL,
                FileName TEXT NOT NULL,
                PathName TEXT NOT NULL,
                Verified BOOLEAN NOT NULL
                )
            ''')

    def add_file(self, client_id, file_name: str, path_name: str):
        """Add or update a file in the database."""
        with self.connection:
            # Check if an entry with the same ID, FileName, and PathName already exists
            cursor = self.connection.execute('''
                SELECT 1 FROM FILE_TABLE WHERE ID = ? AND FileName = ? AND PathName = ?
            ''', (client_id, file_name, path_name))

            if cursor.fetchone() is None:
                # Insert a new row if the combination doesn't exist
                self.connection.execute('''
                    INSERT INTO FILE_TABLE (ID, FileName, PathName, Verified)
                    VALUES (?, ?, ?, ?)
                ''', (client_id, file_name, path_name, False))

    def verify_file(self, client_id, file_name: str, path_name: str):
        """Verify a file's CRC in the database."""
        with self.connection:
            self.connection.execute('''
            UPDATE FILE_TABLE
            SET Verified = ?
            WHERE ID = ? AND FileName = ? AND PathName = ?
            ''', (True, client_id, file_name, path_name))

    def check_user_exists(self, name: str) -> bool:
        """Check whether a user exists."""
        cursor = self.connection.cursor()
        cursor.execute('SELECT 1 FROM CLIENT_TABLE WHERE Name = ?', (name,))
        return cursor.fetchone() is not None

    def check_login(self, client_id: bytes, name: str) -> bool:
        """Check whether a user and his public key exists."""
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT Name
            FROM CLIENT_TABLE
            WHERE ID = ? AND Name = ?
            AND PublicKey IS NOT NULL AND PublicKey != ?
            ''', (client_id, name, b''))
        return cursor.fetchone() is not None

    def get_public_key(self, client_id: bytes) -> bytes:
        """Get the public key of a user."""
        cursor = self.connection.cursor()
        cursor.execute('SELECT PublicKey FROM CLIENT_TABLE WHERE ID = ?', (client_id,))
        result = cursor.fetchone()
        if result is None:
            raise KeyError(f'No public key found for client {client_id}')

        self.update_last_seen(client_id)
        return result[0]

    def add_client(self, name: str) -> bool:
        """Add a new client to the database."""
        if self.check_user_exists(name):
            return False

        with self.connection:
            self.connection.execute('''
                INSERT INTO CLIENT_TABLE (ID, Name, PublicKey, LastSeen, AES_Key)
                VALUES (NULL, ?, NULL, ?, NULL)
            ''', (name, datetime.now().isoformat()))

        return True

    def update_last_seen(self, client_id: bytes):
        """Update the last seen timestamp of a client."""
        with self.connection:
            self.connection.execute('''
                UPDATE CLIENT_TABLE
                SET LastSeen = ?
                WHERE ID = ?
            ''', (datetime.now().isoformat(), client_id))

    def update_client_id(self, client_id: bytes, name: str):
        """update the client ID of a client."""
        with self.connection:
            self.connection.execute('''
            UPDATE CLIENT_TABLE
            SET ID = ?
            WHERE Name = ?
            ''', (client_id, name))

    def update_public_key(self, client_id: bytes, name: str, public_key: bytes):
        """Update the public key of a client."""
        with self.connection:
            self.connection.execute('''
            UPDATE CLIENT_TABLE
            SET PublicKey = ?
            WHERE ID = ? AND Name = ?
            ''', (public_key, client_id, name))

    def update_aes_key(self, client_id: bytes, name: str, aes_key: bytes):
        """Update the AES key of a client."""
        with self.connection:
            self.connection.execute('''
            UPDATE CLIENT_TABLE
            SET AES_Key = ?
            WHERE ID = ? AND Name = ?
            ''', (aes_key, client_id, name))

    def delete_client(self, param):
        """Delete a client from the database."""
        with self.connection:
            if isinstance(param, bytes):
                self.connection.execute('''
                DELETE FROM CLIENT_TABLE WHERE ID = ?
                ''', (param,))

            elif isinstance(param, str):
                self.connection.execute('''
                DELETE FROM CLIENT_TABLE WHERE Name = ?
                ''', (param,))


    def get_client(self, client_id):
        """Retrieve client details by ID."""
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT ID, Name, PublicKey, LastSeen, AES_Key
            FROM CLIENT_TABLE
            WHERE ID = ?
        ''', (client_id,))
        return cursor.fetchone()

    def close(self):
        """Close the database connection."""
        self.connection.close()
