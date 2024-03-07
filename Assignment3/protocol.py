import random


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
        """
        self._key = None
        self.g = 5  # i am unsure about this value
        self.p = 23  # i am unsure about this value
        self.R = None

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
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # Claris
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text
