# tshare.js
This module implements (2,3) XOR threshold secret sharing for splitting secrets into three shares. None of the shares alone give away any information about the secret (other than the length) but any combination of two shares is able to fully recover the secret.

This is a pure JavaScript implementation compatible with the [Golang version](https://github.com/wybiral/tshare).
