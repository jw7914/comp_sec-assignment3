import oqs
import json

class Order:
    def __init__(self, order_id, customer, items, total):
        self.__order_id = order_id
        self.__customer = customer
        self.__items = items
        self.__total = total
        self.__order_data = self.create_order_data()

    # Creates a JSON representation for the order
    def create_order_data(self):  
        order_data = {
            "order_id": self.__order_id,
            "customer": self.__customer,
            "items": self.__items,
            "total": self.__total
        }
        return json.dumps(order_data, sort_keys=True)
    
    # Return order_data as bytes
    def get_order_data(self):
        return self.__order_data.encode('utf-8')
    
    # Temporary setter for tampering simulation
    def set_total(self, total):
        self.__total = total
        self.__order_data = self.create_order_data()  # Recreate the order data after tampering

# Simulate order placement process
def order_demo():
    # Create a new order
    order = Order(order_id="12345", customer="Bob", 
                  items=[{"name": "Coke", "quantity": 2}, {"name": "Sprite", "quantity": 3}], 
                  total=10.00)
    print(f"Original order data: {order.create_order_data()}")
    
    # Initialize the SPHINCS+ signer and sign the order
    alg = "SPHINCS+-SHA2-256f-simple"
    with oqs.Signature(alg) as signer:
        signer_public_key = signer.generate_keypair() # Signer generates its keypair
        order_signed = signer.sign(order.get_order_data())
        print(f"Order created and signed using {alg}")

    # Verify the order (before tampering)
    with oqs.Signature(alg) as verifier:
        is_valid = verifier.verify(order.get_order_data(), order_signed, signer_public_key)
        print(f"Verify the order (before tampering): {'Pass' if is_valid else 'Fail'}\n")
    
    # Simulating tampering (changing total)
    order.set_total(200.00) 
    print(f"Tampered order data: {order.create_order_data()}")
    with oqs.Signature(alg) as verifier:
        is_valid = verifier.verify(order.get_order_data(), order_signed, signer_public_key)
        print(f"Verify the order (after tampering): {'Pass' if is_valid else 'Fail'}\n")


order_demo()

"""
OUTPUT
Original order data: {"customer": "Bob", "items": [{"name": "Coke", "quantity": 2}, {"name": "Sprite", "quantity": 3}], "order_id": "12345", "total": 10.0}        
Order created and signed using SPHINCS+-SHA2-256f-simple
Verify the order (before tampering): Pass

Tampered order data: {"customer": "Bob", "items": [{"name": "Coke", "quantity": 2}, {"name": "Sprite", "quantity": 3}], "order_id": "12345", "total": 200.0}       
Verify the order (after tampering): Fail
"""