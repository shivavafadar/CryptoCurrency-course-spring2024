from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode

def generate_rsa_key_pair():
    # Generate an RSA key pair with a key size of 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Get the public key from the private key
    public_key = private_key.public_key()

    return private_key, public_key

def asymmetric_encryptor(input_message: bytes, public_key):
    try:
        # Convert message to bytes (if needed)
        if not isinstance(input_message, bytes):
            input_message = input_message.encode()
        # Encrypt the message
        encrypted_message = public_key.encrypt(
            input_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Encode the encrypted message in base64
        cipher_text = b64encode(encrypted_message).decode()
        return cipher_text
    except Exception as e:
        print("Encryption failed:", e)
        return None

def asymmetric_decryptor(input_ciphertext: str, private_key):
    try:
        if input_ciphertext is None:
            return None
        # Decode the base64 encoded ciphertext
        encrypted_message = b64decode(input_ciphertext)
        # Decrypt the ciphertext using RSA decryption with OAEP padding
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Decode the plaintext message
        plain_text = decrypted_message.decode()
        return plain_text
    except Exception as e:
        print("Decryption failed:", e)
        return None

def asymmetric_verifier(plaintext: str, ciphertext: str, public_key, private_key):
    # Verify the correctness of the decryption process by
    # comparing the original message with the decrypted message.
    # Output should be a boolean (True or False)
    result = asymmetric_decryptor(ciphertext, private_key)
    if result == plaintext:
        return True
    else:
        return False

# Generate RSA key pair
private_key, public_key = generate_rsa_key_pair()

# Read data from the file
with open('confidential-message.txt', 'rb') as file:
    input_message = file.read()

# Test encryption code:
encrypted_message = asymmetric_encryptor(input_message, public_key)
print("Encrypted Message:", encrypted_message)

# Test decryption code:
decrypted_message = asymmetric_decryptor(encrypted_message, private_key)
print("Decrypted Message:", decrypted_message)

# Test verification code:
result = asymmetric_verifier(input_message.decode(), encrypted_message, public_key, private_key)
print("Verification result:", result)
