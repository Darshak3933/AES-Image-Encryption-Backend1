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

@app.route('/decrypt', methods=['POST'])
def decrypt():
    print(request.files['image'] is None)
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    
    encrypted_file = request.files['image']
    key = request.form['key']

    if len(key) not in (16, 24, 32):
        return jsonify({'error': 'Invalid key length'}), 400

    # Read the encrypted file
    encrypted_image = encrypted_file.read()

    # Split the IV and the actual encrypted data
    iv = encrypted_image[:16]  # The first 16 bytes are the IV
    encrypted_image = encrypted_image[16:]  # The rest is the encrypted data

    # Decrypt the image
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    decrypted_image_bytes = unpad(cipher.decrypt(encrypted_image), AES.block_size)

    # Convert decrypted bytes back to an image
    decrypted_image = Image.open(io.BytesIO(decrypted_image_bytes))
    decrypted_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_image.png')
    decrypted_image.save(decrypted_image_path)
    
    # Encode the decrypted data to base64 to send back to the frontend
    decrypted_image = base64.b64encode(decrypted_data).decode('utf-8')

    # Return the decrypted image for download
    return send_file(decrypted_image_path, as_attachment=True)

if __name__ == "__main__":
    app.run()
