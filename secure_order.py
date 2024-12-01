import oqs

# Algorithm to use: SPHINCS+
algorithm = "SPHINCS+-SHAKE-256f-simple"

# Function to generate a key pair
def generate_keypair(signer):
    # Generate key pair (public and private)
    public_key = signer.generate_keypair()
    private_key = signer.export_secret_key()
    return public_key, private_key

# Function to sign order data (private key is inherently used by signer)
def sign_order_data(order_data, signer):
    # Sign the order data
    return signer.sign(order_data)

# Function to verify order data using public key
def verify_order_data(order_data, signature, signer, public_key):
    return signer.verify(order_data, signature, public_key)

# Main function to secure and verify e-commerce order data
def secure_order_data(order_data):
    # Create a signer for SPHINCS+
    with oqs.Signature(algorithm) as signer:
        # Generate public and private key pair
        public_key, private_key = generate_keypair(signer)
        print(f"Public key: {len(public_key)} bytes")
        print(f"Private key: {len(private_key)} bytes")

        # Sign the order data
        signature = sign_order_data(order_data, signer)
        print(f"Signature: {len(signature)} bytes")

        # Verify the signature using the public key
        is_valid = verify_order_data(order_data, signature, signer, public_key)
        print(f"Signature valid for original order data: {is_valid}")

        # Demonstrate tampering detection
        tampered_order_data = order_data.replace(b"Jane Doe", b"John Doe")
        is_valid_tampered = verify_order_data(tampered_order_data, signature, signer, public_key)
        print(f"Signature valid for tampered order data: {is_valid_tampered}")

# Simulated e-commerce order data
order_data = b"""
Order ID: 12345
Customer: Jane Doe
Item: Quantum Laptop
Amount: $100
Date: 2024-11-30
"""

# Secure the order data
secure_order_data(order_data)
