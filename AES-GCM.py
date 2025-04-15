from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import base64
import hashlib
from datetime import datetime
import os

# Padding helpers
def pad(data, block_size=16):
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

# Generate random image
def generate_random_image(width, height, filename):
    data = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
    img = Image.fromarray(data, 'RGB')
    img.save(filename)
    return filename

# Show image metadata
def display_image_metadata(image_path):
    try:
        img = Image.open(image_path)
        print("\nImage Metadata:")
        print(f"Format       : {img.format}")
        print(f"Mode         : {img.mode}")
        print(f"Size         : {img.size[0]} x {img.size[1]}")
        print(f"Color Depth  : {len(img.getbands()) * 8} bits")
        size_kb = os.path.getsize(image_path) / 1024
        print(f"File Size    : {size_kb:.2f} KB")
    except Exception as e:
        print("Metadata Error:", e)

# AES-GCM encryption
def aes_gcm_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

# AES-GCM decryption
def aes_gcm_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Embed data into image
def embed_data_in_image(image_path, data, output_path):
    img = Image.open(image_path).convert('RGB')
    img_data = np.array(img).flatten()
    data_len = len(data)
    metadata = data_len.to_bytes(4, 'big')
    combined = metadata + data
    if len(combined) * 8 > len(img_data):
        raise ValueError("Image too small for the data.")
    for i in range(len(combined)):
        byte = combined[i]
        for bit in range(8):
            bit_val = (byte >> (7 - bit)) & 1
            img_data[i * 8 + bit] = (img_data[i * 8 + bit] & 0xFE) | bit_val
    new_data = img_data.reshape(img.size[1], img.size[0], 3)
    Image.fromarray(new_data).save(output_path)

# Extract data from image
def extract_data_from_image(image_path):
    img = Image.open(image_path)
    data = np.array(img).flatten()
    bits = [data[i] & 1 for i in range(32)]
    meta_bytes = bytearray()
    for i in range(0, 32, 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        meta_bytes.append(byte)
    length = int.from_bytes(meta_bytes, 'big')
    bits = [data[i] & 1 for i in range(32, 32 + length * 8)]
    message = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        message.append(byte)
    return bytes(message)

# Main loop
while True:
    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ").strip().lower()

    if choice == 'e':
        message = input("Enter secret message: ").strip().encode()
        timestamp = datetime.utcnow().isoformat()
        msg_with_ts = message + b"|" + timestamp.encode()

        sha_hash = hashlib.sha256(msg_with_ts).digest()
        key = get_random_bytes(16)
        nonce, ciphertext, tag = aes_gcm_encrypt(msg_with_ts, key)
        combined = ciphertext + nonce + tag + sha_hash

        cover_image_path = generate_random_image(256, 256, "cover_image.png")
        output_image_path = "output_image.png"
        embed_data_in_image(cover_image_path, combined, output_image_path)

        print("\n Encryption complete.")
        print("Key (save this securely):", base64.b64encode(key).decode())
        display_image_metadata(output_image_path)

        if input("Decrypt now? (yes/no): ").strip().lower() == 'yes':
            key_input = base64.b64decode(input("Enter base64 decryption key: ").strip())
            extracted = extract_data_from_image(output_image_path)
            ciphertext = extracted[:-64]
            nonce = extracted[-64:-48]
            tag = extracted[-48:-32]
            sha_hash_stored = extracted[-32:]

            try:
                decrypted = aes_gcm_decrypt(nonce, ciphertext, tag, key_input)
                msg_part, ts_part = decrypted.rsplit(b"|", 1)
                now = datetime.utcnow()
                sent = datetime.fromisoformat(ts_part.decode())
                if (now - sent).total_seconds() > 300:
                    raise Exception("⚠️ Replay attack detected: stale message!")
                print("\nDecrypted Message:", msg_part.decode())
                print("SHA-256 Match    :", hashlib.sha256(decrypted).digest() == sha_hash_stored)
            except Exception as e:
                print(" Decryption failed:", str(e))

        if input("\nEncrypt another message? (yes/no): ").strip().lower() != 'yes':
            break

    elif choice == 'd':
        img_path = input("Enter encrypted image path: ").strip()
        key_input = base64.b64decode(input("Enter base64 decryption key: ").strip())
        extracted = extract_data_from_image(img_path)
        ciphertext = extracted[:-64]
        nonce = extracted[-64:-48]
        tag = extracted[-48:-32]
        sha_hash_stored = extracted[-32:]

        try:
            decrypted = aes_gcm_decrypt(nonce, ciphertext, tag, key_input)
            msg_part, ts_part = decrypted.rsplit(b"|", 1)
            now = datetime.utcnow()
            sent = datetime.fromisoformat(ts_part.decode())
            if (now - sent).total_seconds() > 300:
                raise Exception("⚠️ Replay attack detected: stale message!")
            print("\nDecrypted Message:", msg_part.decode())
            print("SHA-256 Match    :", hashlib.sha256(decrypted).digest() == sha_hash_stored)
            display_image_metadata(img_path)
        except Exception as e:
            print(" Decryption failed:", str(e))

    else:
        print("Invalid choice. Please enter 'E' or 'D'.")
