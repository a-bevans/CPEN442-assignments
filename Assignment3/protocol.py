import random
import sys

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

class Protocol:
    
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    # Generate g, p, and R_a/R_b
    # Nadia
    def __init__(self):
        """
        Initializes the Protocol class with default values for g, p, and R.

        Attributes:
        - g (int): The generator value.
        - p (int): The prime modulus.
        - R (int): A nonce value used in the protocol.
        - hmac_key(bytes): key for MAC authentication tag
        """
        self._key = None
        self.shared_key = None
        self.g = 5  # i am unsure about this value
        self.p = 23  # i am unsure about this value
        self.secret = random.randint(1, self.p - 1)
        self.R = None
        self.hmac_key = get_random_bytes(16)
        self.phase = 0

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # Nadia
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        """
        Generates the protocol initiation message containing g, p, and R.

        Returns:
        - str: A string containing g, p, and R separated by commas.
        """
        # Generate a random value R within the range (1, p-1) as the nonce
        
        self.SetSessionKey(self.shared_key)
        self.R = random.randint(1, self.p - 1)
        self.phase = 2
        print(f"Sending init message: R: {self.R}, g: {self.g}, p: {self.p}")
        return f"{self.g},{self.p},{self.R}"


    # Checking if a received message is part of your protocol (called from app.py)
    # Alex
    # Assume there is no message loss, so we can assume that the first message is the initiation message
    # Until the key is established, we can assume that all messages are part of the protocol
    def IsMessagePartOfProtocol(self, tag):
        if self.phase != 4 and tag != b'\x00' * 32:
            return True
        else:
            return False


    # Processing protocol message
    # Alex
    # Server Phases: 
    # 0: Recieved init from client. Encrypt R_client and g^b mod p with the shared key and self.R in the clear and send it to the client
    # 1: Decrypt self.R, g^a mod p from client message. Verify self.R. Calculate g^ab mod p and set to key
    # Client Phases:
    # 2: Decrypt g^b mod p, and self.R from server message. Verify R_self. Encrypt R_server and g^a mod p with the shared key and send it to the server
    #       Set key to g^ab mod p.
    # 4: Finished protocol
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message, tag, nonce):
        try:
            if self.phase == 0:
                print("Phase 0")
                self.SetSessionKey(self.shared_key)
                message = self.DecryptAndVerifyMessage(message, tag, nonce)
                g, p, R = message.split(",")
                self.g = int(g)
                self.p = int(p)
                R = int(R)
                print(f"Recieved init message: R: {R}, g: {self.g}, p: {self.p}")
                self.R = random.randint(1, self.p - 1)
                dh = pow(self.g, self.secret, self.p)
                encrypted = f"{R},{dh},{self.R}"
                self.phase = 1
                print("Phase 0 Message:")
                print(encrypted)
                return encrypted
            
            elif self.phase == 1:
                print("Phase 1")
                message = self.DecryptAndVerifyMessage(message, tag, nonce)
                R_server, dh_client = message.split(",")
                dh_client = int(dh_client)
                R_server = int(R_server)
                if R_server != self.R:
                    raise ValueError
                self.SetSessionKey(pow(dh_client, self.secret, self.p))
                self.phase = 4
                return "Protocol Finished"
            elif self.phase == 2:
                print("Phase 2")
                message = self.DecryptAndVerifyMessage(message, tag, nonce)
                dh_server, R_client = message.split(",")
                dh_server = int(dh_server)
                R_client = int(R_client)
                print(f"Recieved phase 2 message: R: {R_client}, g^a mod p: {dh_server}")
                if R_client != self.R:
                    raise ValueError
                self.SetSessionKey(pow(dh_server, self.secret, self.p))
                self.phase = 4
                return "Protocol Finished"
            else:
                return "Error: Authentication failed"
            

        except ValueError:
            print("Error: Integrity verification or authentication failed.")
        else:
            return plain_text


    # Setting the key for the current session
    # Alex
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = self.extendKey(key)


    # Encrypting messages
    # Claris
    # IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS

    # Documentation: https://pycryptodome.readthedocs.io/en/latest/src/examples.html
    def EncryptAndProtectMessage(self, plain_text):
        print("Encrypting and protecting message:")
        if self._key is None:
            print("Encrypt: No key established.")
            plain_text = plain_text.encode()
            return b'\x00' * 32 + b'\x00' * 8 + plain_text
        try:
            plain_text_bytes = plain_text.encode()
            cipher = AES.new(self._key, AES.MODE_CTR)
            cipher_text = cipher.encrypt(plain_text_bytes)

            hmac = HMAC.new(self.shared_key.encode(), digestmod=SHA256)
            nonce = cipher.nonce
            tag = hmac.update(nonce + cipher_text).digest()

        except Exception as e:
            print("Error: Integrity verification or authentication failed.")

        else:
            return tag + nonce + cipher_text


    # Decrypting and verifying messages
    # Claris
    # IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
        
    # Documentation: https://pycryptodome.readthedocs.io/en/latest/src/examples.html
    def DecryptAndVerifyMessage(self, cipher_text, tag, nonce):
        print("Decrypting and verifying message:")
        if self._key is None:
            print("Decrypt: No key established.")
            return cipher_text
        try:
            hmac = HMAC.new(self.shared_key.encode(), digestmod=SHA256)
            tag = hmac.update(nonce + cipher_text).verify(tag)
            print("Tag verified")

            cipher = AES.new(self._key, AES.MODE_CTR, nonce=nonce)
            message = cipher.decrypt(cipher_text)
            print("Message decrypted")
            plain_text = message.decode()
            print(f"Decrypted message: {plain_text}")

        except ValueError:
            print("Error: Integrity verification or authentication failed.")
        else:
            return plain_text


    def extendKey(self, key):
        h = SHA256.new()
        h.update(key.encode())
        return h.digest()