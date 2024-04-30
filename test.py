from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


def generate_key_pair():
    key_size = 2048  # Should be at least 2048
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Do not change
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


class Server:

    def __init__(self):
        self.keyword = ""

    def initiate_connection(self):
        self.keyword = bytes("lasagna", 'UTF-8')
        return self.keyword

    def authenticate(self, message_encrypted, private_key):
        try:
            message_decrypted = private_key.decrypt(
                message_encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if message_decrypted == self.keyword:
                return "It's all good!"
        except ValueError:
            return "Failed to Decrypt"


class Client:

    def __init__(self):
        self.private_key, self.public_key = generate_key_pair()

    def encrypt_message(self, message):
        return self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )


client, server = Client(), Server()
message = server.initiate_connection()
encrypted_message = client.encrypt_message(message)
print(client.private_key.public_key(), client.private_key)
false_private_key, false_public_key = generate_key_pair()
print(server.authenticate(encrypted_message, client.private_key))
print(server.authenticate(encrypted_message, false_private_key))