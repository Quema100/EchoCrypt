import sys
import argparse
import logging
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

    parser.add_argument('--encrypt', action='store_true', help='Run the encryption process (simulation phase).')
    parser.add_argument('--decrypt', action='store_true', help='Run the decryption process (restoration phase).')
    parser.add_argument('--setup-test-env', action='store_true', help='Generate dummy files for testing purposes.')
    parser.add_argument('--cleanup-test-env', action='store_true', help='Clean up the test environment (including test_files and logs).')
    parser.add_argument('--target-dir', type=str, default=None,
                        help='Specify the directory to target for encryption or decryption.\n'
                            'If not provided, the default "test_files" directory will be used.\n'
                            '**Warning: Never point to system root or critical directories!**')
    parser.add_argument('--num-dummy-files', type=int, default=5, help='Set the number of dummy files to generate (default: 5).')

    args = parser.parse_args()

    actions = [args.encrypt, args.decrypt, args.setup_test_env, args.cleanup_test_env]
    if sum(actions) > 1:
        logger.error("Only one operation (--encrypt, --decrypt, --setup-test-env, --cleanup-test-env) can be specified at a time.")
        parser.print_help()
        sys.exit(1)

    if not any(actions):
        logger.warning("No operation specified. Use --help to see usage instructions.")
        parser.print_help()
        sys.exit(0)

    simulator = Ransomware(args.target_dir)

    if args.setup_test_env:
        simulator.run_setup(args.num_dummy_files)
    elif args.encrypt:
        simulator.run_encryption()
    elif args.decrypt:
        simulator.run_decryption()
    elif args.cleanup_test_env:
        simulator.run_cleanup()

    logger.info("echocrypt Ransomware program exited.")

if __name__ == "__main__":
    main()