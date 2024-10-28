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

        # Encode the encrypted data to base64 to send over JSON
        encrypted_image = base64.b64encode(ciphertext).decode('utf-8')
        return jsonify({"encrypted_image": encrypted_image})

    except Exception as e:
        print("Encryption error:", e)
        return jsonify({"error": "An error occurred during encryption."}), 500

if __name__ == "__main__":
    app.run()
