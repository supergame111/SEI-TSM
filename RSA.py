#!/usr/bin/env python


from Crypto.Hash import SHA
from Crypto.PublicKey import RSA

h = SHA.new()
h.update("Hello")
hash = h.hexdigest()

print hash

key = RSA.importKey(open('keys/privatekey.pem', 'r'))

print key.encrypt(hash, None)
print key.sign(hash, None)
print key.decrypt(key.encrypt(hash, None)[0])
print key.decrypt(key.sign(hash, None)[0])
