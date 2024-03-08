import random

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
        self.g = 5  # i am unsure about this value
        self.p = 23  # i am unsure about this value
        self.R = None
        self.hmac_key = get_random_bytes(16)

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
        self.R = random.randint(1, self.p - 1)
        return f"{self.g},{self.p},{self.R}"


    # Checking if a received message is part of your protocol (called from app.py)
    # Alex
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return False


    # Processing protocol message
    # Alex
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        pass


    # Setting the key for the current session
    # Alex
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # Claris
    # IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS

    # Documentation: https://pycryptodome.readthedocs.io/en/latest/src/examples.html
    def EncryptAndProtectMessage(self, plain_text):

        try:
            plain_text_bytes = plain_text.encode()
            cipher = AES.new(self._key, AES.MODE_CTR)
            cipher_text = cipher.encrypt(plain_text_bytes)

            hmac = HMAC.new(self.hmac_key, digestmod=SHA256)
            nonce = cipher.nonce
            tag = hmac.update(nonce + cipher_text).digest()

        except Exception as e:
            print("Error: Integrity verification or authentication failed.")

        else:
            return cipher_text, tag, nonce


    # Decrypting and verifying messages
    # Claris
    # IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
        
    # Documentation: https://pycryptodome.readthedocs.io/en/latest/src/examples.html
    def DecryptAndVerifyMessage(self, cipher_text, tag, nonce):

        try:
            hmac = HMAC.new(self.hmac_key, digestmod=SHA256)
            tag = hmac.update(nonce + cipher_text).verify(tag)

            cipher = AES.new(self._key, AES.MODE_CTR, nonce=nonce)
            message = cipher.decrypt(cipher_text)
            plain_text = message.decode()

        except ValueError:
            print("Error: Integrity verification or authentication failed.")
        else:
            return plain_text
