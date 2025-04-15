from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import base64

# Helper functions for padding and unpadding
def pad(data, block_size=16):
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

# Encrypt data using SM4 (AES in ECB mode for simplicity)
def sm4_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

# Decrypt data using SM4
def sm4_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data))

# Embed data into an image (including metadata)
def embed_data_in_image(image_path, data, output_path):
    img = Image.open(image_path)
    img = img.convert('RGB')
    img_data = np.array(img)
    
    # Flatten the image array
    flat_img = img_data.flatten()
    
    # Prepare metadata (length of the encrypted data, 4 bytes)
    data_length = len(data)
    metadata = data_length.to_bytes(4, 'big')  # Store length in 4 bytes
    
    # Combine metadata and data
    combined_data = metadata + data
    if len(combined_data) * 8 > len(flat_img):
        raise ValueError("Data is too large to fit in the image.")

    # Embed the combined data into the image
    for i in range(len(combined_data)):
        byte = combined_data[i]
        for bit_pos in range(8):
            bit = (byte >> (7 - bit_pos)) & 0x01
            flat_img[i * 8 + bit_pos] = (flat_img[i * 8 + bit_pos] & 0xFE) | bit
    
    # Reshape and save the new image
    new_img_data = flat_img.reshape(img_data.shape)
    new_img = Image.fromarray(new_img_data, 'RGB')
    new_img.save(output_path)

# Extract data from an image (including metadata)
def extract_data_from_image(image_path):
    img = Image.open(image_path)
    img_data = np.array(img).flatten()
    
    # Extract metadata (first 4 bytes for data length)
    metadata_bits = []
    for i in range(32):  # 4 bytes * 8 bits
        metadata_bits.append(img_data[i] & 0x01)
    
    metadata_bytes = bytearray()
    for i in range(0, len(metadata_bits), 8):
        byte = 0
        for bit in metadata_bits[i:i+8]:
            byte = (byte << 1) | bit
        metadata_bytes.append(byte)
    
    data_length = int.from_bytes(metadata_bytes, 'big')
    
    # Extract encrypted data
    data_bits = []
    for i in range(32, 32 + data_length * 8):
        data_bits.append(img_data[i] & 0x01)
    
    data = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = 0
        for bit in data_bits[i:i+8]:
            byte = (byte << 1) | bit
        data.append(byte)
    
    return bytes(data)

# Main logic
if __name__ == "__main__":
    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ").lower()

    if choice == 'e':
        # Encryption
        input_text = input("Enter the text to hide: ").encode()
        input_image_path = input("Enter the path of the cover image: ")
        output_image_path = "output_image.png"

        # Generate a random 16-byte key for encryption
        key = get_random_bytes(16)
        
        print(f"Generated Key (Keep this safe!): {base64.b64encode(key).decode()}")

        # Encrypt the text
        encrypted_text = sm4_encrypt(input_text, key)
        print(f"Encrypted text: {encrypted_text}")

        # Embed the encrypted text into the image
        embed_data_in_image(input_image_path, encrypted_text, output_image_path)
        print(f"Data hidden in {output_image_path}.")

    elif choice == 'd':
        # Decryption
        encrypted_image_path = input("Enter the path of the encrypted image: ")
        key_input = input("Enter the decryption key: ")

        # Decode the key
        try:
            key = base64.b64decode(key_input)
            if len(key) != 16:
                raise ValueError("Invalid key length.")
        except Exception as e:
            print(f"Error: {e}")
            exit()

        # Extract the data
        try:
            extracted_data = extract_data_from_image(encrypted_image_path)
            decrypted_text = sm4_decrypt(extracted_data, key).decode()
            print(f"Decrypted text: {decrypted_text}")
        except Exception as e:
            print(f"Decryption failed: {e}")
