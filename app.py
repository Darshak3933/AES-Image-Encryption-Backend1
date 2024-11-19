from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
import base64

app = Flask(__name__)
CORS(app)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        # Retrieve the key and image data
        key = request.form.get('key')
        image = request.files.get('image')

        if not key or not image:
            return jsonify({"error": "Key and image file are required."}), 400

        # Ensure the key length is 16, 24, or 32 bytes for AES
        if len(key) not in [16, 24, 32]:
            return jsonify({"error": "Invalid key length. Must be 16, 24, or 32 bytes."}), 400

        key = key.encode('utf-8')
        image_data = image.read()

        # Encrypt the image data
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(image_data)

        # Combine nonce (IV) and ciphertext for decryption later
        encrypted_data = cipher.nonce + ciphertext

        # Encode the encrypted data to base64 to send over JSON
        encrypted_image = base64.b64encode(encrypted_data).decode('utf-8')
        return jsonify({"encrypted_image": encrypted_image})

    except Exception as e:
        print("Encryption error:", e)
        return jsonify({"error": "An error occurred during encryption."}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        encrypted_file = request.files.get('encrypted_image')  # Match frontend key
        key = request.form.get('key')

        if not key or not encrypted_file:
            return jsonify({"error": "Key and encrypted image file are required."}), 400

        # Ensure the key length is valid
        if len(key) not in (16, 24, 32):
            return jsonify({"error": "Invalid key length. Must be 16, 24, or 32 bytes."}), 400

        encrypted_data = base64.b64decode(encrypted_file.read())

        # Split nonce and ciphertext
        nonce = encrypted_data[:16]  # Extract nonce
        ciphertext = encrypted_data[16:]  # Extract ciphertext

        # Decrypt the image
        cipher = AES.new(key.encode(), AES.MODE_EAX, nonce=nonce)
        decrypted_image_bytes = cipher.decrypt(ciphertext)

        # Encode the decrypted data to base64 to send back to the frontend
        decrypted_image = base64.b64encode(decrypted_image_bytes).decode('utf-8')
        return jsonify({"decrypted_image": decrypted_image})

    except Exception as e:
        print("Decryption error:", e)
        return jsonify({"error": "An error occurred during decryption."}), 500

if __name__ == "__main__":
    app.run()
