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

## Password Storage

## Key Generation
