from flask import Flask, request, render_template, jsonify, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import io
import os

app = Flask(__name__)

UPLOAD_FOLDER = './static/images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400

    image_file = request.files['image']
    key = request.form['key']

    if len(key) not in (16, 24, 32):
        return jsonify({'error': 'Invalid key length'}), 400

    # Load and encrypt the image
    image = Image.open(image_file)
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format='PNG')
    image_bytes = img_byte_arr.getvalue()

    # Encrypt the image
    cipher = AES.new(key.encode(), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(image_bytes, AES.block_size))
    iv = cipher.iv
    encrypted_image = iv + ct_bytes

    # Save the encrypted image to a file
    encrypted_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_image.png')
    with open(encrypted_image_path, 'wb') as f:
        f.write(encrypted_image)

    # Return the encrypted file for download
    return send_file(encrypted_image_path, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt():
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

    # Return the decrypted image for download
    return send_file(decrypted_image_path, as_attachment=True)

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
