import oqs
import json


class Order:
    """Represents an e-commerce order with quantum-safe integrity checks."""
    def __init__(self, order_id, customer, items, total):
        self.__order_id = order_id
        self.__customer = customer
        self.__items = items
        self.__total = total
        self.__order_data = self.__create_order_data()

    def __create_order_data(self):
        """Creates a JSON representation of the order."""
        order_data = {
            "order_id": self.__order_id,
            "customer": self.__customer,
            "items": self.__items,
            "total": self.__total
        }
        return json.dumps(order_data, sort_keys=True)

    def get_order_data(self):
        """Returns the JSON order data as bytes."""
        return self.__order_data.encode('utf-8')

    def update_total(self, new_total):
        """Updates the total value and regenerates the order data."""
        self.__total = new_total
        self.__order_data = self.__create_order_data()


class DigitalSignature:
    """Handles quantum-safe signing and verification of data."""
    def __init__(self, algorithm="SPHINCS+-SHA2-256f-simple"):
        self.algorithm = algorithm
        self.signer = oqs.Signature(self.algorithm)
        self.public_key = None
        self.secret_key = None

    def generate_keys(self):
        """Generates a keypair for the specified algorithm."""
        self.public_key = self.signer.generate_keypair()
        self.secret_key = self.signer.export_secret_key()

    def sign(self, data):
        """Signs the given data."""
        return self.signer.sign(data)

    def verify(self, data, signature):
        """Verifies the given signature against the data."""
        with oqs.Signature(self.algorithm) as verifier:
            return verifier.verify(data, signature, self.public_key)


def secure_order_demo():
    """Demonstrates secure order creation, signing, and verification."""
    # Step 1: Create an order
    order = Order(
        order_id="12345",
        customer="Alice",
        items=[{"name": "Laptop", "quantity": 1}, {"name": "Mouse", "quantity": 1}],
        total=1500.00
    )
    print(f"Original Order Data: {order.get_order_data().decode('utf-8')}\n")

    # Step 2: Generate keys and sign the order
    signer = DigitalSignature()
    signer.generate_keys()
    signed_order = signer.sign(order.get_order_data())
    print(f"Order signed using {signer.algorithm}.")
    print(f"Signature: {len(signed_order)} bytes\n")

    # Step 3: Verify the original order
    is_valid_original = signer.verify(order.get_order_data(), signed_order)
    print(f"Verification of original order: {'Pass' if is_valid_original else 'Fail'}\n")

    # Step 4: Simulate tampering and verify again
    order.update_total(5000.00)  # Tampered total
    print(f"Tampered Order Data: {order.get_order_data().decode('utf-8')}\n")

    is_valid_tampered = signer.verify(order.get_order_data(), signed_order)
    print(f"Verification of tampered order: {'Pass' if is_valid_tampered else 'Fail'}\n")


if __name__ == "__main__":
    secure_order_demo()
