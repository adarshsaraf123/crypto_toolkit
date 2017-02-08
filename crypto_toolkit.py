'''
Created on 14-Jan-2017

@author: adarsh
'''
import hashlib
import os
import base64
import base58
from privad.exceptions import IncorrectPasswordError
# We will be using base58 encoding for all our keys as is the convention followed in protocols
# like Bitcoin, Ripple, BigchainDB for human readability 

USE_SCRYPT = False

# generate_keypair is used in other modules; we want to club all the crypto utilities together
# here
from bigchaindb_driver.crypto import generate_keypair
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import UnsupportedAlgorithm, InvalidKey
 
class Base58Encoder(object):

    @staticmethod
    def encode(data):
        return base58.b58encode(data).encode()

    @staticmethod
    def decode(data):
        return base58.b58decode(data)
 
# def hash_password(password):
#     '''
#     To generate the salted hash of the parameter password.
#     Returns the hashed password.
#     
#     We use uuid to generate a random salt.
#     The salt is suffixed to the generated hash after a ':'
#     '''
#     # uuid is used to generate a random number
#     salt = get_random_number()
#     return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt
#     
# def check_password(hashed_password, user_password):
#     '''
#     To check if the user supplied user_password matches the hashed_password available.
#     Returns True is the password supplied is correct else False.
#     '''
#     password, salt = hashed_password.split(':')
#     return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()

def get_random_number(size = 16):
    '''
    Get a random number.
    The size parameter specifies the number of bytes in the random number generated.
    The default size of 16 is acceptable for salts, etc. 
    Returns the Base58 encoded random number.
    '''
    return Base58Encoder.encode(os.urandom(size))

def generate_key_from_password(password, salt = None, length = 128, iterations = 100000):
    '''
    Given the password (`bytes`) to be used for key derivation and an optional salt this function
    derives the key using the PBKDF2HMAC kdf from the cryptography library. 
    
    If the salt is not specified then we generate it randomly using os.random of length
    16 bytes (hence 128 bits). 
    
    The key length can also be optionally specified with the default value of 128.
    
    Returns a (key, salt) tuple where the key is a (base58 encoded) `bytes` array.
    
    We return only the salt and not the length and iterations since the user is expected to know
    the other two while the salt might not have been specified by the user and hence has to be
    informed of the salt. To keep the interface uniform we return the salt even when the salt
    has been specified by the user.   
    '''
    backend = default_backend()
    if not isinstance(password, bytes):
        password = password.encode()
    if salt is None:
        salt = get_random_number()    
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length = length,
            salt = salt,
            iterations = iterations,
            backend = backend )
    key = kdf.derive(password)
    # Base58 encode the key
    return (Base58Encoder.encode(key), salt)

def verify_key_from_password(key, password, salt, length = 128, iterations = 100000):
    '''
    Verify if the key (base58 encoded) has been obtained from the password and the salt (and other parameters).
    Raises an InvalidKey exception if the key is not correct.  
    '''
    backend = default_backend()
    if not isinstance(password, bytes):
        password = password.encode()
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length = length,
            salt = salt,
            iterations = iterations,
            backend = backend )
    # decode the Base58encode key
    try: 
        kdf.verify(password, Base58Encoder.decode(key))
    except InvalidKey:
        raise IncorrectPasswordError('given password and salt do not generate the given key')    
    
def generate_storage_hash_from_password(password, salt = None, length = 128, n = 2**14,
                                        r = 8, p = 1 ):
    '''
    Given a password (`bytes`) and an optional salt this function
    derives the storage hash to be used for storing the password using the Scrypt kdf from
    the cryptography library. 
    
    If the salt is not specified then we generate it randomly using os.random of length
    16 bytes (hence 128 bits). 
    
    The key length can also be optionally specified with the default value of 128.
    The other parameters are specific to scrypt and are as follows:
    
    
    Returns a (key, salt) tuple where the key is a `bytes` array.
    
    We return only the salt and not the length and iterations since the user is expected to know
    the other two while the salt might not have been specified by the user and hence has to be
    informed of the salt. To keep the interface uniform we return the salt even when the salt
    has been specified by the user.
    
    '''
    backend = default_backend()
    if not isinstance(password, bytes):
        password = password.encode()
    if salt is None:
        salt = get_random_number()
    
    if USE_SCRYPT:    
        kdf = Scrypt(salt = salt,
                    length = length,
                    n = 2**14,
                    r = 8,
                    p = 1,
                    backend = backend)
        storage_hash = kdf.derive(password)
        # Base58 encode the storage hash
        return (Base58Encoder.encode(storage_hash), salt)
    else:
        # this implies that scrypt is not available in the openssl version installed in the 
        # system. scrypt is available only from version 1.1 of openssl. Please consider
        # upgrading your openssl version to 1.1.
        # we fallback to generating the key using PBKDF2 from above.
        return generate_key_from_password(password, salt)

def verify_storage_hash_from_password(storage_hash, password, salt, length = 128):
    '''
    Verify if the given `storage_hash` matches that generated by the given password and salt 
    (and other parameters).
    Raises an InvalidKey exception if the key is not correct. 
    '''
    backend = default_backend()
    if not isinstance(password, bytes):
        password = password.encode()
    if USE_SCRYPT:  
        kdf = Scrypt(
                    salt = salt,
                    length = length,
                    n = 2**14,
                    r = 8,
                    p = 1,
                    backend = backend)
        # Base58 decode the storage_hash
        try:
            kdf.verify(password, Base58Encoder.decode(storage_hash))
        except InvalidKey:
            raise IncorrectPasswordError('given password and salt do not generate the storage_hash') 
    else:
        # this implies that scrypt is not available in the openssl version installed in the 
        # system. scrypt is available only from version 1.1 of openssl.
        # Please consider upgrading your openssl version to 1.1.
        # We fallback to verification using PBKDF2 for verification.
        try:
            verify_key_from_password(storage_hash, password, salt, length)
        except IncorrectPasswordError:
            raise IncorrectPasswordError('given password and salt do not generate the storage_hash')
    

if __name__ == '__main__':
    password = 'sairam123'
    salt = b'4b6kctx8B9AkiT6zqxxce9'
    (key, salt) = generate_key_from_password(password, salt)
    print(key, '\n', salt)
    verify_key_from_password(key, password, salt)
    (storage_hash, salt) = generate_storage_hash_from_password(password, salt)
    print(storage_hash, '\n',salt)
    verify_storage_hash_from_password(storage_hash, password, salt)
    

    