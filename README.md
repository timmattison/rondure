# Rondure

Rondure is an elliptic curve cryptography (ECC) implementation that supports the standard NIST curves over F<sub>p</sub>.  It does not support curves over F<sub>2<sup>m</sup></sub>.  It was ported from [a very nice Javascript implementation](http://www-cs-students.stanford.edu/~tjw/jsbn/) and therefore uses the same BSD license.

## Motivation

I felt that the libraries available that let people play with ECC in Java were a bit weird to work with.  I also wanted to play around with the curves that Bitcoin and Tor use.

## Is it secure?

I'm not a cryptographer (seriously!) so I only know that I appear to have done the following:

- Ported the Javascript code to Java
- Implemented a test suite that passes with all of the test vectors from:
    - [point-at-infinity](http://point-at-infinity.org/ecc/nisttv) for the NIST P-* curves
    - [crypto.stackexchange.com](http://crypto.stackexchange.com/questions/784/are-there-any-secp256k1-ecdsa-test-examples-available) for secp256k1

Should you use this for critical software?  No.

## How can I use it?

Look at the test code.  I may post examples here in the future.

### Other stuff

We use [Travis CI](https://travis-ci.org/) because it is cool.
