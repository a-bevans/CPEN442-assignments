import random
import sys

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

class Protocol:
    
    def __init__(self):
        """
        Initializes the Protocol class with default values for g, p, and R.
        Generates a random secret value for the Diffie-Hellman key exchange.

        Attributes:
        - g (int): The base value for the Diffie-Hellman key exchange.
        - p (int): The prime modulus for the Diffie-Hellman key exchange.
        - R (int): The random value used as a nonce in the protocol.
        - secret (int): The secret value used in the Diffie-Hellman key exchange.
        - shared_key (str): The shared key used to encrypt and decrypt messages.
        - phase (int): The phase of the protocol.
        - dh_recieved (int): The value received from the other party in the Diffie-Hellman key exchange.
        - hmac_key (str): The key used to generate HMACs for message integrity.
        """
        self._key = None
        self.shared_key = None
        self.g = 5  
        self.p = 23  
        self.secret = random.randint(1, self.p - 1)
        print(f"Secret: {self.secret}")
        self.R = random.randint(1, self.p - 1)
        print(f"R: {self.R}")
        self.hmac_key = get_random_bytes(16)
        self.phase = 0
        self.dh_recieved = None


    def GetProtocolInitiationMessage(self):
        """
        Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
        Returns:
        - the initial message of the protocol.
        """
        # Generate a random value R within the range (1, p-1) as the nonce
        
        self.SetSessionKey(self.shared_key)
        self.phase = 2
        print(f"Sending init message: R: {self.R}, g: {self.g}, p: {self.p}")
        return f"{self.g},{self.p},{self.R}"


    def IsMessagePartOfProtocol(self, tag):
        """
        Checking if a received message is part of the protocol by seeing if the tag is the set buffer value or
        the protocol is finished (called from app.py).
        Returns:
        - True if the message is part of the protocol.
        - False if the message is not part of the protocol.
        """
        if tag != b'\x00' * 32 and self.phase != 5:
            return True
        else:
            return False


    def ProcessReceivedProtocolMessage(self, message, tag, nonce):
        """
        Processing a received message as part of the protocol.
        Server Phases: 
            0: Received init from client. Encrypt R_client and g^b mod p with the shared key and self.R in the clear and send it to the client
            1: Decrypt self.R, g^a mod p from client message. Verify self.R. Calculate g^ab mod p and set to key
        Client Phases:
            2: Decrypt g^b mod p, and self.R from server message. Verify R_self. Encrypt R_server and g^a mod p with the shared key and send it to the server
            Set key to g^ab mod p.
        Shared Phases:
            4: Set the new session key
            5: Protocol Finished
        Returns:
        - the response message to be sent back to the other party.
        """
        try:
            if self.phase == 0:
                print("Phase 0")
                self.SetSessionKey(self.shared_key)
                message = self.DecryptAndVerifyMessage(message, tag, nonce)
                g, p, R = message.split(",")
                self.g = int(g)
                self.p = int(p)
                R = int(R)
                print(f"Received init message: R: {R}, g: {self.g}, p: {self.p}")
                dh = pow(self.g, self.secret, self.p)
                encrypted = f"{R},{dh},{self.R}"
                self.phase = 1
                print("Phase 0 Message:")
                print(encrypted)
                return encrypted
            
            elif self.phase == 1:
                print("Phase 1")
                message = self.DecryptAndVerifyMessage(message, tag, nonce)
                R_test, dh_client = message.split(",")
                self.dh_recieved = int(dh_client)
                R_test = int(R_test)
                if R_test != self.R:
                    raise ValueError
                self.phase = 4
                return "Protocol Finished"
            
            elif self.phase == 2:
                print("Phase 2")
                message = self.DecryptAndVerifyMessage(message, tag, nonce)
                print(f"Decrypted message: {message}")
                R_test, dh_server, R_client = message.split(",")
                R_test = int(R_test)
                self.dh_recieved = int(dh_server)
                R_client = int(R_client)
                #print(f"Recieved phase 2 message: R: {R_client}, g^a mod p: {dh_server}")
                if R_test != self.R:
                    print("Error: R_self does not match")
                    raise ValueError
                message = f"{R_client},{pow(self.g, self.secret, self.p)}"
                print(f"Sending phase 2 message: R: {R_client}, g^a mod p: {pow(self.g, self.secret, self.p)}")
                self.phase = 4
                return message
            elif self.phase == 4:
                print("Phase 4")
                self.SetSessionKey(f"{pow(self.dh_recieved, self.secret, self.p)}")
                self.phase = 5
                return "Protocol Finished"
            else:
                return "Error: Authentication failed"
            

        except ValueError:
            print("ProcessError: Integrity verification or authentication failed.")
        else:
            return message


    def SetSessionKey(self, key):
        """
        Sets the key for the current session.
        Args:
        - key (str): The key to be used for the current session.
        """
        self._key = self.extendKey(key)
        print(f"Session key set: {self._key}")


    def EncryptAndProtectMessage(self, plain_text):
        """
        Encrypts and protects a message using the session key.
        Implements encryption with the session key and includes necessary info in the encrypted message for integrity protection.
        Documentation: https://pycryptodome.readthedocs.io/en/latest/src/examples.html
        Args:
        - plain_text (str): The message to be encrypted and protected.
        Throws:
        - EncodeError: If integrity verification or authentication fails.
        Returns:
        - the encrypted and protected message.  
        """
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
            print("EncodeError: Integrity verification or authentication failed.")

        else:
            return tag + nonce + cipher_text


    def DecryptAndVerifyMessage(self, cipher_text, tag, nonce):
        """
        Decrypts and verifies a message using the session key.
        Implements decryption with the session key and includes necessary info in the encrypted message for integrity protection.
        Returns an error message if integrity verification or authentication fails.
        Documentation: https://pycryptodome.readthedocs.io/en/latest/src/examples.html
        Args:
        - cipher_text (str): The message to be decrypted and verified.
        - tag (str): The tag used to verify the integrity of the message.
        - nonce (str): The nonce used to decrypt the message.
        Throws:
        - DecodeError: If integrity verification or authentication fails.
        Returns:
        - the decrypted and verified message.
        """
        print("Decrypting and verifying message:")
        if self._key is None:
            print("Decrypt: No key established.")
            return cipher_text.decode()
        try:
            hmac = HMAC.new(self.shared_key.encode(), digestmod=SHA256)
            hmac.update(nonce + cipher_text)
            hmac.verify(tag)
            print("Tag verified")

            cipher = AES.new(self._key, AES.MODE_CTR, nonce=nonce)
            message = cipher.decrypt(cipher_text)
            print("Message decrypted")
            plain_text = message.decode()
            print(f"Decrypted message: {plain_text}")

        except Exception as e:
            print("DecodeError: Integrity verification or authentication failed.")
        else:
            return plain_text


    def extendKey(self, key):
        """
        Extends the key to the required length.
        Args:
        - key (str): The key to be extended.
        Returns:
        - the extended key.
        """
        h = SHA256.new()
        h.update(key.encode())
        return h.digest()