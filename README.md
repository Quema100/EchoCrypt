# EchoCrypt

This project, **EchoCrypt**, is a **ransomware simulation** designed for **educational purposes only**.  
It aims to demonstrate the fundamental principles and mechanisms of file encryption, key exfiltration to a simulated server, and the decryption process as seen in real-world ransomware attacks.  

> [!WARNING]    
> **DO NOT use this code on any system containing important data.**  
> **DO NOT distribute or use this code for any malicious or illegal activities.**  
> **ALWAYS run this code in a highly isolated and controlled environment, such as a dedicated virtual machine (VM) with no network access to your primary systems.**  
> This simulation modifies files on your system. Using the `--setup-test-env` option and a dedicated `--target-dir` is **STRONGLY RECOMMENDED** to prevent accidental damage.  
> **The developer is not responsible for any misuse of this software or any damage caused thereby.**  

## Table of Contents

* [Introduction](#introduction)
* [Features](#features)
* [Project Structure](#project-structure)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Usage](#usage)
    * [1. Server Simulation (Optional but Recommended)](#1-Server-Simulation-Optional-but-Recommended)
    * [2. Setup Test Environment](#2-setup-test-environment)
    * [3. Encrypt Files (Infection Phase)](#3-encrypt-files-infection-phase)
    * [4. Decrypt Files (Restoration Phase)](#4-decrypt-files-restoration-phase)
    * [5. Clean Up Test Environment](#5-clean-up-test-environment)
* [Technical Details](#technical-details)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)

## Introduction

EchoCrypt is a Python-based project that simulates the behavior of a typical ransomware attack. It demonstrates key stages: generating cryptographic keys, encrypting target files, exfiltrating the private key to a Command & Control server, generating a ransom note, and providing a decryption utility. This tool is designed to help understand ransomware mechanisms.

## Features

* **RSA Key Pair Generation:** Generates a new RSA public/private key pair for each infection.
* **AES-256 File Encryption:** Uses AES in CBC mode with a randomly generated key and IV for each file.
* **Key Exfiltration Simulation:** Simulates exfiltrating the RSA private key and decryption password to a remote server (requires a simple Express server setup).
* **Layered Key Protection:** Encrypts the per-file AES key with RSA, and then encrypts the RSA-encrypted AES key with a password-derived key (PBKDF2-HMAC).
* **Ransom Note Generation:** Creates a realistic ransom note (`README.txt`) with instructions, a victim ID, and payment details (simulated).
* **Encryption Metadata:** Stores metadata (encrypted AES keys, IVs, salts) for each encrypted file in a JSON file, crucial for decryption.
* **Automated Test Environment Setup/Cleanup:** Provides utilities to create dummy files for testing and clean them up afterward.
* **Logging:** Comprehensive logging to `echocrypt.log` and console for tracking simulation steps and debugging.

## Project Structure
``` bash
EchoCrypt/
├── main.py   
├── test.py
├── modules/
│   ├── ransomware.py 
│   ├── constants.py 
│   └── __init__.py         
├── test_files/             
├── server.js
├── stolen_keys/            
└── echocrypt.log       
```    

## Prerequisites

* Python 3.10+
* `pip` (Python package installer)
* Node.js 22.16+
* `npm` (Node Package Manager)

## Installation

1.  **Clone the repository:** (If this is from a GitHub repo)
    ```bash
    git clone [https://github.com/Quema100/EchoCrypt.git](https://github.com/Quema100/EchoCrypt.git)
    cd echocrypt
    ```
    (If you received the files directly, just navigate to the project directory.)

2.  **Install dependencies:**
    ```bash
    pip install cryptography requests 
    npm i express
    ```

## Usage

All operations are performed via `test.py` with command-line arguments.

### 1. Server Simulation (Optional but Recommended)

For the key exfiltration feature to work, you need a simulated server running.    
Open a **separate terminal window** and run:

```bash
npm start
```
The server will start at **http://127.0.0.1:3000/password**.   
It will log received keys and save them in the stolen_keys/ directory. Keep this terminal open during the encryption phase.

### 2. Setup Test Environment
HIGHLY RECOMMENDED to create a dedicated directory with dummy files for safe testing.

```Bash
python test.py --setup-test-env --target-dir my_test_data
```

This will create `my_test_data/` and fill it with several dummy files specified in `constants.py`.  
If `--target-dir` is omitted, it defaults to `test_files/`.

### 3. Encrypt Files (Infection Phase)

This simulates the ransomware infection.  It will generate keys, attempt to exfiltrate the private key, and encrypt files in the target directory.

```bash
python test.py --encrypt --target-dir my_test_data
```
Upon successful encryption, `my_test_data/` will contain encrypted files (with `.echocrypt` extension), `README.txt`, `public_key.pem`, and `encryption_metadata.json`.

> [!IMPORTANT]
> The simulated decryption password and victim ID will be printed to the console during this step (and exfiltrated to the server).  
> Note them down for decryption. 

### 4. Decrypt Files (Restoration Phase)
This simulates the decryption process, requiring the private key (obtained from the server simulation) and the decryption password.

Steps:

1. Locate the exfiltrated private key from your server simulation (e.g., `stolen_keys/VICTIM_ID_YOUR_IP_private_key.pem`).

2. Copy this private key file into the same directory as the `public_key.pem` file. For this example, assume it is copied as `private_key.pem`.

3. Run the decryption command:

    ```bash
    python test.py --decrypt
    ```
4. The program will prompt you to enter the decryption password (the one noted during the encryption phase).

If successful, the encrypted files will be restored to their original state, and the ransom note, metadata, private key, and public key files will be deleted.

### 5. Clean Up Test Environment

To remove all generated files and directories (including encrypted/decrypted files, logs, and metadata) from your target directory:

```bash
python test.py --cleanup-test-env --target-dir my_test_data
```
This will remove the my_test_data/ directory entirely.

## Technical Details
* Key Derivation: PBKDF2-HMAC (SHA256) is used to derive an AES key from a password and salt.

* Symmetric Encryption: AES-256 in CBC mode for file content.

* Asymmetric Encryption: RSA-2048 using OAEP padding for encrypting the per-file AES keys.

* Exfiltration: requests library is used for HTTP POST requests to the server simulation.

*  Threading: A separate thread handles the exfiltration to avoid blocking the main encryption process.

## Contributing
Feel free to fork this repository, open issues, and submit pull requests. Suggestions for improving realism, security education, or code quality are welcome.

## Contact
For questions or discussions related to this simulation, please open an issue in the GitHub repository.