# Contents
1. [Random Number Generation](#Random-Number_Generation)
2. [Password Storage](#Password-Storage)
3. [Key Generation](#Key-Generation)

## Random Number Generation

`/dev/random` or `/dev/urandom` are considered very good sources for random numbers.
From the Linux man page:

> The random number generator gathers environmental noise from device drivers and other sources into an entropy pool.
> The generator also keeps an estimate of the number of bits of noise in the entropy pool.
> From this entropy pool, random numbers are created... 

`/dev/random` is blocking until environmental noise is available.
`/dev/urandom` is non-blocking and can reuse the internal pool to produce more pseudo-random bits when new ones are not available. 
For futher info on these look at the [man-page](http://man7.org/linux/man-pages/man4/random.4.html).

`/dev/urandom` can be accessed through the python `os` module as follows:
``` python
import os
random_number = os.urandom(16)
```
For further info look at [`os.urandom`](https://docs.python.org/3/library/os.html).

In this toolkit we have provided the following method for users to easily get pseudorandom numbers:
``` python 
get_random_number(size = 16):
    '''
    Get a random number.
    The size parameter specifies the number of bytes in the random number generated.
    The default size of 16 is acceptable for salts, etc. 
    Returns the Base58 encoded random number.
    '''
``` 
Currently it's a wrapper around `os.urandom` but can be updated in the future to support better random number generators.

## Password Storage

It is never advisable to store user passwords in plaintext in any manner. Any user password must immediately be garbled to safeguard it's security. The current practices require that we store a hash of the password generated. This can be done using either of `PBKDF2`, `bcrypt`, or `scrypt` cryptographic tools. While `PBKDF2` is secure, it is vulnerable to ASICs/GPUs based attacks since it does not use more memory but just repetitive computations. It is suggested that passwords be hashed using `scrypt` which has larger memory requirements. All these methods use a unique salt per password to prevent against _rainbow attacks_, which involves the creation of inverse hash tables. The use of the salt makes it difficult to precompute inverse hashes since now the salt varies and therefore any attacker will have to compute the hashes based on this salt, which is effectively a brute-force attack and is made very difficult since finding collisions for cryptographically secure hash funtions is computationally difficult.

`PBKDF2` can take any pseudorandom function like cryptographic hash, ciphers or hash-based message authentication code to garble the given password using the salt. For more details, see [`PBKDF2`](https://en.wikipedia.org/wiki/PBKDF2 "Wikipedia").

In the given toolkit, we provide the following two methods:
``` python
generate_storage_hash_from_password(password, salt = None, length = 128, n = 2**14, r = 8, p = 1)
verify_storage_hash_from_password(storage_hash, password, salt, length = 128)
```
These can be used to provide the functionalities of generating and verifying storage hashes for passwords. The user can supply the salt, or a random salt is generated using `get_random_number`.

## Key Generation
