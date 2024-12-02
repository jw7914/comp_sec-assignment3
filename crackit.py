import oqs
import json
import os
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QuantumSafeOrderSystem:
    def __init__(self, sig_alg="SPHINCS+-SHAKE-256f-simple"):
        logger.info(f"Initializing QuantumSafeOrderSystem with signature algorithm: {sig_alg}")
        self.sig_alg = sig_alg
        self.signer = oqs.Signature(self.sig_alg)
        self.public_key = self.signer.generate_keypair()
        self.private_key = self.signer.export_secret_key()
        self.orders = {}
        logger.debug(f"Public key length: {len(self.public_key)} bytes")
        logger.debug(f"Private key length: {len(self.private_key)} bytes")

    def load_order_data(self, filename='./order_data.json'):
        logger.info(f"Attempting to load order data from {filename}")
        try:
            with open(filename, 'r') as json_file:
                data = json.load(json_file)
                logger.info(f"Successfully loaded order data from {filename}")
                return data
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON: {e}")
            logger.error(f"Error occurred at line {e.lineno}, column {e.colno}")
            return None
        except FileNotFoundError:
            logger.error(f"File {filename} not found.")
            return None

    def create_order(self, order_data):
        logger.info("Creating new order")
        order_id = order_data['order_id']

        static_fields = {
            'order_id': order_data['order_id'],
            'customer_name': order_data['customer_name'],
            'customer_email': order_data['customer_email'],
            'customer_phone': order_data['customer_phone'],
            'shipping_address': order_data['shipping_address'],
            'payment_method': order_data['payment_method'],
            'payment_details': order_data['payment_details'],
            'product_details': order_data['product_details'],
            'order_date': order_data['order_date'],
            'subtotal': order_data['subtotal'],
            'tax_rate': order_data['tax_rate'],
            'tax_amount': order_data['tax_amount'],
            'total_price': order_data['total_price']
        }

        static_json = json.dumps(static_fields, sort_keys=True)
        logger.debug(f"Static fields JSON: {static_json}")

        signature = self.signer.sign(static_json.encode())
        logger.debug(f"Signature length: {len(signature)} bytes")

        order_json = json.dumps(order_data)
        salt = os.urandom(16)
        logger.debug(f"Generated salt: {salt.hex()}")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = kdf.derive(self.private_key)
        logger.debug(f"Derived key length: {len(key)} bytes")

        iv = os.urandom(16)
        logger.debug(f"Generated IV: {iv.hex()}")
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(order_json.encode()) + encryptor.finalize()
        logger.debug(f"Encrypted data length: {len(encrypted_data)} bytes")

        self.orders[order_id] = {
            'encrypted_data': b64encode(encrypted_data).decode(),
            'signature': b64encode(signature).decode(),
            'salt': b64encode(salt).decode(),
            'iv': b64encode(iv).decode()
        }

        logger.info(f"Order created with ID: {order_id}")
        return order_id

    def verify_order(self, order_id):
        logger.info(f"Verifying order with ID: {order_id}")

        if order_id not in self.orders:
            logger.warning(f"Order not found: {order_id}")
            return False, "Order not found"

        order = self.orders[order_id]

        encrypted_data = b64decode(order['encrypted_data'])
        signature = b64decode(order['signature'])
        salt = b64decode(order['salt'])
        iv = b64decode(order['iv'])

        logger.debug(f"Retrieved encrypted data length: {len(encrypted_data)} bytes")
        logger.debug(f"Retrieved signature length: {len(signature)} bytes")

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = kdf.derive(self.private_key)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        logger.debug(f"Decrypted data length: {len(decrypted_data)} bytes")

        order_data = json.loads(decrypted_data.decode())

        static_fields = {
            'order_id': order_data['order_id'],
            'customer_name': order_data['customer_name'],
            'customer_email': order_data['customer_email'],
            'customer_phone': order_data['customer_phone'],
            'shipping_address': order_data['shipping_address'],
            'payment_method': order_data['payment_method'],
            'payment_details': order_data['payment_details'],
            'product_details': order_data['product_details'],
            'order_date': order_data['order_date'],
            'subtotal': order_data['subtotal'],
            'tax_rate': order_data['tax_rate'],
            'tax_amount': order_data['tax_amount'],
            'total_price': order_data['total_price']
        }

        static_json = json.dumps(static_fields, sort_keys=True)

        try:
            is_valid = self.signer.verify(static_json.encode(), signature, self.public_key)
            logger.info(f"Signature verification result: {'Valid' if is_valid else 'Invalid'}")
            return is_valid, order_data if is_valid else "Invalid signature"
        except oqs.SignatureVerificationError:
            logger.error("Signature verification failed")
            return False, "Signature verification failed"

    def update_order(self, order_id, new_data):
        logger.info(f"Updating order {order_id} with new data: {new_data}")

        if order_id not in self.orders:
            logger.warning(f"Order not found: {order_id}")
            return False, "Order not found"

        order = self.orders[order_id]
        encrypted_data = b64decode(order['encrypted_data'])
        salt = b64decode(order['salt'])
        iv = b64decode(order['iv'])

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = kdf.derive(self.private_key)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        original_order = json.loads(decrypted_data.decode())
        updated_order = {**original_order, **new_data}

        tampered_order_json = json.dumps(updated_order)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        tampered_encrypted_data = encryptor.update(tampered_order_json.encode()) + encryptor.finalize()

        self.orders[order_id]['encrypted_data'] = b64encode(tampered_encrypted_data).decode()

        logger.warning(f"Tampered order data for ID: {order_id}")
        return True, "Tampered order data successfully"

logger.info("Starting QuantumSafeOrderSystem demo")
order_system = QuantumSafeOrderSystem()

logger.info("Loading order data")
order_data = order_system.load_order_data()
if order_data:
    logger.info("Creating new order")
    order_id = order_system.create_order(order_data)
    logger.info(f"Order created with ID: {order_id}")

    logger.info("Verifying the created order")
    is_valid, verified_data = order_system.verify_order(order_id)
    logger.info(f"Order verification: {'Valid' if is_valid else 'Invalid'}")
    logger.debug(f"Verified data: {verified_data}")

    logger.info("Updating the order with a dynamic field")
    update_result, update_message = order_system.update_order(order_id, {"order_status": "Processing"})
    logger.info(f"Dynamic field update: {update_message}")
    logger.info("Verifying the updated order")
    is_valid, verified_data = order_system.verify_order(order_id)
    logger.info(f"Updated order verification: {'Valid' if is_valid else 'Invalid'}")
    logger.debug(f"Updated verified data: {verified_data}")

    logger.info("Updating the order with a static field")
    update_result, update_message = order_system.update_order(order_id, {"customer_name": "Wu"})
    logger.info(f"Static field update: {update_message}")
    logger.info("Verifying the updated order")
    is_valid, verified_data = order_system.verify_order(order_id)
    logger.info(f"Updated order verification: {'Valid' if is_valid else 'Invalid'}")
    logger.debug(f"Updated verified data: {verified_data}")

else:
    logger.error("Failed to load order data. Exiting.")
