# Cross-Platform Backup System

## Overview
The Cross-Platform Backup System is a secure file transfer application that enables encrypted data transfer and storage between a Python-based server and a C++ client. It ensures data integrity while providing efficient user and file management.

## Features
- **Secure File Transfer**: Implements end-to-end encryption for safe data transfer.
- **Cross-Platform Compatibility**: Seamlessly integrates Python (server) and C++ (client) for broad usability.
- **User and File Management**: Maintains a structured database for users and file tracking.
- **Version Control**: Tracks file versions for better backup management.
- **Data Integrity**: Validates and preserves data accuracy throughout the transfer process.

## Technology Stack
- **Server**: Python
- **Client**: C++
- **Database**: SQLite
- **Encryption**: AES-CBC, RSA

## Installation
### Prerequisites
- Python 3.x
- C++ compiler
- Boost library installed
- Required C++ library Crypto++
- Required Python library PyCryptodome

## Usage
- Start the server and connect the client to initiate file transfer.
- Use the transfer.info file to choose a username and which file to send to the server.
- Transfer and retrieve files with encryption.

## Future Improvements
- Implement a GUI for easier user interaction.
- Add support for additional encryption methods.
- Enhance logging and monitoring capabilities.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Contributors
- @Leon Gold

---
Feel free to contribute or raise issues to improve the system!

