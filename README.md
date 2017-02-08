# crypto_toolkit
A set of cryptographic tools exposed in a simple user interface for most common usages. 

## Background
We create this simple toolkit in order to enable users exploit cryptographic techniques for data security without actually having to know about them. We provide simple APIs for common use scenarios using the Python `cryptography` module.

## Requirements
You should have the Python [`cryptography`](https://pypi.python.org/pypi/cryptography) module installed in the environment you are working. It you have `pip` installed in your system, this can be installed using:
```
[sudo] pip install cryptography
```
We recommend the use of [`virtualenv`](https://pypi.python.org/pypi/virtualenv) to create a separate virtual environment for your project. It can be installed using:
```
[sudo] pip install virtualenv
```


## Usage
We are currently maintaining a single module under this project for easy import into your project. Download this project and then import the `crypto_toolkit` module:
```
import crypto_toolkit
```

It currently has the following functions to handle passwords:
* `generate_key_from_password`
* `verify_key_from_password`
* `generate_storage_hash_from_password`
* `verify_storage_hash_from_password`

The names of the functions are intuitive. The above functions are necessary since it is never advisable to store passwords. Any password must immediately converted into a key using a key derivation function (kdfs). Based on our explorations, we found that the common practice is to use **PBKDF2** for key generation, that is use the password to derive a key that can be used further with various encryption techniques, and **scrypt** to generate hashes of passwords that can be stored for password verification. 
