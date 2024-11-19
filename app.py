from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import io
from PIL import Image

app = Flask(__name__)
CORS(app)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        key = request.form.get('key')
        image = request.files.get('image')

        if not key or not image:
            return jsonify({"error": "Key and image file are required."}), 400

        if len(key) not in [16, 24, 32]:
            return jsonify({"error": "Invalid key length. Must be 16, 24, or 32 bytes."}), 400

        key = key.encode('utf-8')
        image_data = image.read()

        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(image_data)

        encrypted_data = cipher.nonce + ciphertext
        encrypted_image = base64.b64encode(encrypted_data).decode('utf-8')
        return jsonify({"encrypted_image": encrypted_image})

    except Exception as e:
        print("Encryption error:", e)
        return jsonify({"error": "An error occurred during encryption."}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        encrypted_file = request.files.get('encrypted_image')
        key = request.form.get('key')

        if not key or not encrypted_file:
            return jsonify({"error": "Key and encrypted image file are required."}), 400

        if len(key) not in [16, 24, 32]:
            return jsonify({"error": "Invalid key length. Must be 16, 24, or 32 bytes."}), 400

        key = key.encode('utf-8')
        encrypted_data = base64.b64decode(encrypted_file.read())

        nonce = encrypted_data[:16]  # Extract nonce (IV)
        ciphertext = encrypted_data[16:]  # Extract ciphertext

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_image_bytes = cipher.decrypt(ciphertext)

        # Validate and load the decrypted bytes as an image
        img_byte_arr = io.BytesIO(decrypted_image_bytes)
        try:
            decrypted_image = Image.open(img_byte_arr)
            decrypted_image.verify()  # Ensure the bytes are a valid image
        except Exception as e:
            print("Decrypted bytes do not form a valid image:", e)
            return jsonify({"error": "Decrypted data is not a valid image."}), 400

        # Convert the decrypted image to base64 for frontend display
        img_byte_arr.seek(0)
        decrypted_image_base64 = base64.b64encode(img_byte_arr.read()).decode('utf-8')

        return jsonify({"decrypted_image": decrypted_image_base64})

    except Exception as e:
        print("Decryption error:", e)
        return jsonify({"error": "An error occurred during decryption."}), 500

if __name__ == "__main__":
    app.run()
