# Pass Gate

A GUI application for Mac and Linux which aims to provide a set of operations for handling user secrets.

## Motivation

Handling dozens of secrets in a secure and convenient way may represent quite a challenge nowadays.
This application is another approach to ease this difficulty while pursuing strong cryptographical standards.
The design goal of this utility is to provide a set of common operations that can be combined to get the desired result.

## Features

The following futures are supported:

* Generate a secret according to the specified format
* Generate a keyfile
* Generate a BIP39 mnemonic
* Encrypt / decrypt a secret (AES GCM)
* Split / recombine a secret according to the Shamir's Secret Sharing scheme (011B over GF(256))
* Type the password into a password field (Linux only)
* Split the secret into parts of the same size during the view process
* Clear clipboard upon exit

The utility may use one of the following entropy sources for performing cryptographic operations:

* Random Number Generator (PKCS11 or OpenSSL)
* RSA Signature (PKCS 11, PKCS 12, PKCS 8) with HKDF-SHA-512
* BIP39 mnemonic

## Dependencies

* [Qt6](https://www.qt.io)
* [OpenSSL](https://www.openssl.org/)
* [xdotool](https://github.com/jordansissel/xdotool)

## Screenshot

![PassGate Screenshot](/PassGateScreenshot.png?raw=true "PassGate Screenshot")

## Password format

```
___ ___ ___ ___ ___
 |   |   |   |   |
 |   |   |   |   -- special chars alphabet
 |   |   |   |        a: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
 |   |   |   |        h: !#$%&()*+/<>?@[\]^{}~
 |   |   |   |        s: !#$%&*@^
 |   |   |   |        x: <not used>
 |   |   |   |
 |   |   |   ------ digits alphabet
 |   |   |            a: 0123456789
 |   |   |            h: 23456789
 |   |   |            x: <not used>
 |   |   |
 |   |   ---------- lower chars alphabet
 |   |                a: abcdefghijklmnopqrstuvwxyz
 |   |                h: abcdefghijkmnpqrstuvwxyz
 |   |                x: <not used>
 |   |
 |   -------------- upper chars alphabet
 |                    a: ABCDEFGHIJKLMNOPQRSTUVWXYZ
 |                    h: ABCDEFGHJKLMNPQRSTUVWXYZ
 |                    x: <not used>
 |
 ------------------ length of the password
```

## Examples
```
 4xxax:     0788
 8hhhx:     p7yGFFVb
 8xhhx:     vrc4f9v3
 12hhhh:    *Q?3RhWi/9Tz
 16aaaa:    DxmoKy4y_Sr`e"r0
```

