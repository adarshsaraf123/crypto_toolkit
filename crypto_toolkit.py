'''
Created on 14-Jan-2017

@author: adarsh
'''

import hashlib
import os
import base64
import base58
from privad.exceptions import IncorrectPasswordError
from secretsharing.sharing import PlaintextToHexSecretSharer
import ssl
# We will be using base58 encoding for all our keys as is the convention followed in protocols
# like Bitcoin, Ripple, BigchainDB for human readability 

# the scrypt library is available only in OpenSSL v1.1 onwards
# hence we check the openssl version and set the USE_SCRYPT flag is the openssl version is
# greater than 1.1

version1, version2 = map(int, ssl.OPENSSL_VERSION.split()[1].split('.')[:2])
if version1 > 1 and version2 > 1:
    # implies the openssl version is above 1.1 and hence scrypt will be available   
    USE_SCRYPT = True
else:
    USE_SCRYPT = False

NUM_ITERATIONS_PBKDF2 = 100000

# generate_keypair is used in other modules; we want to club all the crypto utilities together
# here
from bigchaindb_driver.crypto import generate_keypair
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from cryptography.hazmat.backends import default_backend, openssl
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import UnsupportedAlgorithm, InvalidKey
 
class Base58Encoder(object):
    '''
    Why Base58 encoding? The original Bitcoin client source code explains:
        < Why base-58 instead of standard base-64 encoding?
        < Don't want 0OIl characters that look the same in some fonts and could be used to create visually identical looking account numbers.
        < A string with non-alphanumeric characters is not as easily accepted as an account number.
        < E-mail usually won't line-break if there's no punctuation to break at.
        < Doubleclicking selects the whole number as one word if it's all alphanumeric.
    '''
    @staticmethod
    def encode(data):
        # base58.b58encode takes bytes as input and returns a string, hence the encode() here to get output as bytes
        return base58.b58encode(data).encode()

    @staticmethod
    def decode(data):
        # base58.b58decode takes bytes/str as input and produces bytes
        return base58.b58decode(data)
 
def get_random_string(size = 16):
    '''
    Get a random string of the specified `size` number of bytes.
    The default size of 16 is acceptable for salts, etc. 
    Returns the random string as bytes.
    '''
    return os.urandom(size)

def generate_key_from_password(password, salt = None, length = 128):
    '''
    Given the password (`bytes`) to be used for key derivation and an optional salt this function
    derives the key using the PBKDF2HMAC kdf from the cryptography library. 
    
    If the salt is not specified then we generate it randomly using os.random of length
    16 bytes (hence 128 bits). 
    
    The key length can also be optionally specified with the default value of 128.
    
    Returns a (key, salt) tuple where the key is a (base58 encoded) `bytes` array, and the salt is base58 encoded.
    
    We return only the salt and not the length since the user is expected to know the length
    while the salt might not have been specified by the user and hence has to be
    informed of the salt. To keep the interface uniform we return the salt even when the salt
    has been specified by the user.   
    '''
    backend = default_backend()
    if not isinstance(password, bytes):
        password = password.encode()
    if salt is None:
        # Base58 encode the salt
        salt = Base58Encoder.encode(get_random_string())    
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length = length,
            salt = salt,
            iterations = NUM_ITERATIONS_PBKDF2,
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
            iterations = NUM_ITERATIONS_PBKDF2,
            backend = backend )
    # decode the Base58encode key
    try: 
        kdf.verify(password, Base58Encoder.decode(key))
    except InvalidKey:
        raise IncorrectPasswordError('given password and salt do not generate the given key')    
    
def generate_storage_hash_from_password(password, salt = None, length = 128):
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
        salt = Base58Encoder.encode(get_random_string())
    
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


def encrypt(symmetric_key, data):
    '''
    Encrypt the given data using AES with the given symmetric key.
    
    Args:
        symmetric_key: Base58 encoded symmetric key to be used for encryption
        data: data to be encrypted of type string or bytes  
    
    We use AES in the CBC mode with a randomly generated iv (initialization vector) of 16 bytes
    (the AES block size). The iv is prepended to the encrypted data and when the encrypted data
    is presented for decryption it must be extracted from there. 
    
    Returns:
        the encrypted data with the iv prepended in bytes format
    '''
    if not isinstance(data, bytes):
        data = data.encode()
    # the given data has to be now padded to fit the block size (128 bits for AES) for encryption
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
        
    backend = default_backend()
    # the AES block size is 128 bits ( = 16 bytes) and the initialization vector must be of the
    # size as the block size 
    iv = get_random_string(16)    
    
    # provide to AES the Base58decoded symmetric_key as that will be of the size as expected by AES
    cipher = Cipher(algorithm = algorithms.AES(Base58Encoder.decode(symmetric_key)),
                            mode= modes.CBC(iv), backend=backend)
    
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return (iv + encrypted_data)
    
def decrypt(symmetric_key, encrypted_data):
    '''
    Decrypt the given data using AES with the given symmetric key.
    
    Args:
        symmetric_key: Base58 encoded symmetric key to be used for encryption
        encrypted_data: data to be encrypted of type bytes  
    
    We use AES in the CBC mode with the iv (initialization vector) of 16 bytes
    (the AES block size) extracted fromt the front of the encrypted data. 
    
    Returns:
        the decrypted data as a bytes object.
    '''
    if not isinstance(encrypted_data, bytes):
        data = encrypted_data.encode()
    backend = default_backend()
    
    # the AES block size is provided in bits, and hence the division by 8 to get the corresponding byte size 
    iv = encrypted_data[:16]    
    encrypted_data = encrypted_data[16:]
    
    # provide to AES the Base58decoded symmetric_key as that will be of the size as expected by AES
    cipher = Cipher(algorithm = algorithms.AES(Base58Encoder.decode(symmetric_key)),
                            mode= modes.CBC(iv), backend=backend)
    
    # decrypt the provided data
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return data    

def secret_sharing(secret, share_threshold = 2, num_shares = 3):
    '''
    To compute the `num_shares` splits of the given `secret` such that only when `share_threshold`
    of these shares come together the given secret can be recovered.
    Args:
        secret: the secret in bytes or str
        share_threshold: the threshold for the number of shares to come together for it to be possible
            to reconstruct the secret
        num_shares: the number of shares to be created
    Returns a list of the shares 
    '''
    if isinstance(secret, bytes):
        secret = secret.decode()
    if share_threshold > num_shares:
        raise ValueError('the share_threshold must be smaller than the num_shares')
    return PlaintextToHexSecretSharer.split_secret(secret, share_threshold, num_shares)

def secret_recovery(shares):
    '''
    To recover the secret string that had been split into shares from a list `shares` of shares.
    Args:
        shares: a list of the shares
    Returns the recovered secret 
    '''
    if not isinstance(shares, list):
        raise ValueError('a list of shares must be provided for secret recovery')
    return PlaintextToHexSecretSharer.recover_secret(shares) 

