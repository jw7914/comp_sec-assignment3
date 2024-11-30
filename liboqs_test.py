import oqs

# Algorithm to use: SPHINCS+
algorithm = "SPHINCS+-SHAKE-256f-simple" 

# Create a signer for SPHINCS+
with oqs.Signature(algorithm) as signer:
    # Generate key pair
    public_key = signer.generate_keypair()
    print(f"Public key: {len(public_key)} bytes")

    # Message to sign
    message = b"Quantum-safe digital signature demo using SPHINCS+"

    # Sign the message
    signature = signer.sign(message)
    print(f"Signature: {len(signature)} bytes")

    # Verify the signature
    is_valid = signer.verify(message, signature, public_key)
    print(f"Signature valid: {is_valid}")

    # Example of tampering to demonstrate verification failure
    tampered_message = b"Tampered message"
    is_valid_tampered = signer.verify(tampered_message, signature, public_key)
    print(f"Tampered signature valid: {is_valid_tampered}")
