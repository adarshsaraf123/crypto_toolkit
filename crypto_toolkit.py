'''
Created on 14-Jan-2017

@author: adarsh
'''
import hashlib
import uuid
import os
# generate_keypair is used in other modules; we want to club all the crypto utilities together
# here
from bigchaindb_driver.crypto import generate_keypair
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
 
def hash_password(password):
    '''
    To generate the salted hash of the parameter password.
    Returns the hashed password.
    
    We use uuid to generate a random salt.
    The salt is suffixed to the generated hash after a ':'
    '''
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt
    
def check_password(hashed_password, user_password):
    '''
    To check if the user supplied user_password matches the hashed_password available.
    Returns True is the password supplied is correct else False.
    '''
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + user_password.encode()).hexdigest()

def generate_key_from_password(password, salt = None, length = 128, iterations = 100000):
    '''
    Given the password (`bytes`) to be used for key derivation and an optional salt this function
    derives the key using the PBKDF2HMAC kdf from the cryptography library. 
    
    If the salt is not specified then we generate it randomly using os.random of length
    16 bytes (hence 128 bits). 
    
    The key length can also be optionally specified with the default value of 128.
    
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
        salt = os.urandom(16)    
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length = length,
            salt = salt,
            iterations = iterations,
            backend = backend )
    key = kdf.derive(password)
    return (key, salt)

def verify_key_from_password(password, salt, length = 128, iterations = 100000):
    '''
    Verify if the key has been obtained from the password and the salt. 
    '''
    
    
def generate_storage_hash_from_password(password, salt = None, length = 128):
    '''
    Given a password (`bytes`) and an optional salt this function
    derives the storage hash to be used for storing the password using the Scrypt kdf from
    the cryptography library. 
    
    If the salt is not specified then we generate it randomly using os.random of length
    16 bytes (hence 128 bits). 
    
    The key length can also be optionally specified with the default value of 128.
    
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
        salt = os.urandom(16)
        
    kdf = Scrypt(
                salt = salt,
                length = length,
                n = 2**14,
                r = 8,
                p = 1,
                backend = backend)
    storage_hash = kdf.derive(password)
    return (storage_hash, salt)

def verify_storage_hash_from_password(password, salt = None, length = 128):
    '''
    Verify if the password generated the given storage hash with the given salt
    (and other parameters).
    '''