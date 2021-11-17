# PassGate

A GUI application for linux to generate a password based on the input data and the certificate

## Principle

This utility signs the input string using the provided certificate and uses this signature as a source of entropy for password generation.

## Features

* Generate a password using the input string and the certificate
* Encrypt a secret using the public key of the certificate
* Generate a keyfile based on the specified input string
* Decrypt the secret using the private key of the certificate
* Type the password into the password field
* Clear clipboard upon exit

## Screenshot

![PassHelper Screenshot](/PassGateScreenshot.png?raw=true "PassGate Screenshot")

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

