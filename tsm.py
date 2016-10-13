#!/usr/bin/env python

from flask import Flask
from flask import jsonify
from flask import request

from binascii import hexlify
from binascii import unhexlify

from Crypto import Random
from Crypto.Cipher import DES3
from Crypto.Cipher import DES


app = Flask(__name__)

gNEWKEYVERSION = 34
gNEWKEY = unhexlify("0B0B0B0B0B0B0B0BD0D0D0D0D0D0D0D0")
# gNEWKEY = unhexlify("BDBDBDBDBDBDBDBDDBDBDBDBDBDBDBDB")

gKEYVERSION = 12
gKEY = unhexlify("404142434445464748494a4b4c4d4e4f")
# gKEY = unhexlify("0B0B0B0B0B0B0B0BD0D0D0D0D0D0D0D0")
KEY_ENC = gKEY
KEY_MAC = gKEY
KEY_DEK = gKEY

gSENC = None
gSMAC = None
gSDEK = None

gSENCIV = unhexlify("0000000000000000")
gSMACIV = unhexlify("0000000000000000")
gSDEKIV = unhexlify("0000000000000000")

gHostChallenge = None

def hexKeyVersion(version):
    version = hex(version)[2:]
    if(len(version) < 2):
        version = "0" + version
    return version

def getKeyversion():
    return hexKeyVersion(gKEYVERSION)

def generateChallenge():
    return hexlify(Random.new().read(8))

@app.route('/tsm/initialize-update')
def initializeUpdate():
    global gHostChallenge
    gHostChallenge = generateChallenge()
    tmpAPDU = "80" + "50" + getKeyversion() + "00" + "08" + gHostChallenge + "00"
    return tmpAPDU


@app.route('/tsm/external-authenticate', methods=['GET'])
def externalAuthenticate():
    global gSENC, gSENCIV
    global gSMAC, gSMACIV
    global gSDEK, gSDEKIV
    tmpResponse = request.args.get('response', None)
    if tmpResponse is None:
        return "args error"
    tmpResponse = unhexlify(tmpResponse)
    tmpSequenceCounter = tmpResponse[12:14]
    tmpCardChallenge = tmpResponse[14:20]
    tmpCardCryptogram = tmpResponse[20:28]
    # S_ENC
    tmpSENC = "0182" + hexlify(tmpSequenceCounter) + '00' * 12
    gSENC = triple_des_encrypt(KEY_ENC, DES3.MODE_CBC, gSENCIV, unhexlify(tmpSENC))
    # S_MAC
    tmpSMAC = "0101" + hexlify(tmpSequenceCounter) + '00' * 12
    gSMAC = triple_des_encrypt(KEY_MAC, DES3.MODE_CBC, gSMACIV, unhexlify(tmpSMAC))
    # S_DEK
    tmpSDEK = "0181" + hexlify(tmpSequenceCounter) + '00' * 12
    gSDEK = triple_des_encrypt(KEY_DEK, DES3.MODE_CBC, gSDEKIV, unhexlify(tmpSDEK))
    # Verify Host Challenge
    tmpLocalCardCryptogram = gHostChallenge + \
            hexlify(tmpSequenceCounter) + \
            hexlify(tmpCardChallenge) + \
            '80' + '00' * 7
    tmpLocalCardCryptogram = triple_des_encrypt(gSENC, DES3.MODE_CBC, gSENCIV, unhexlify(tmpLocalCardCryptogram))
    tmpLocalCardCryptogram = tmpLocalCardCryptogram[-8:]
    if hexlify(tmpCardCryptogram) !=  hexlify(tmpLocalCardCryptogram):
        return "Verify CardCryptogram error!"

    tmpHostCryptogram = hexlify(tmpSequenceCounter) + \
            hexlify(tmpCardChallenge) + \
            gHostChallenge + \
            '80' + '00' * 7
    tmpHostCryptogram = triple_des_encrypt(gSENC, DES3.MODE_CBC, gSENCIV, unhexlify(tmpHostCryptogram))
    tmpHostCryptogram = tmpHostCryptogram[-8:]

    tmpAPDU = "8482" + "01" + "0010" + hexlify(tmpHostCryptogram)
    tmpCMAC = hexlify(retailMac(gSMAC, gSMACIV, unhexlify(tmpAPDU)))
    tmpAPDU = tmpAPDU + tmpCMAC
    gSMACIV = des_encrypt(gSMAC[0:8], DES3.MODE_ECB, None, unhexlify(tmpCMAC))
    return jsonify(s_enc=gSENC.encode('hex'), s_mac=gSMAC.encode('hex'), \
            s_dek=gSDEK.encode('hex'), apdu=tmpAPDU, cmaciv=hexlify(gSMACIV))

@app.route('/tsm/delete-key', methods=['GET'])
def delete():
    global gSMAC
    global gSMACIV
    if hexKeyVersion(gNEWKEYVERSION).upper() == "0C":
        return "Can not delete the test key!"
    tmpAPDU = "84" + "E4" + "00" + "00"
    tmpKeyDataField = "D0" + "01" + hexKeyVersion(gNEWKEYVERSION)
    tmpAPDU = tmpAPDU + "0B" + tmpKeyDataField
    tmpCMAC = hexlify(retailMac(gSMAC, gSMACIV, unhexlify(tmpAPDU)))
    tmpAPDU = tmpAPDU + tmpCMAC + "00"
    gSMACIV = des_encrypt(gSMAC[0:8], DES3.MODE_ECB, None, unhexlify(tmpCMAC))
    # Force check dangerous
    if tmpAPDU[12:14].upper() == "0C":
        return "Can not delete the test key!"
    return tmpAPDU

@app.route('/tsm/put-key', methods=['GET'])
def putKey():
    global gSDEK
    global gSMAC
    global gSMACIV
    global gNEWKEY
    if getKeyversion().upper() == "0C":
        return "Keep the test key!"
    tmpMode = request.args.get('mode', None)
    if tmpMode is None:
        return "args error"
    tmpMode = tmpMode.upper()
    if tmpMode not in ['ADD', 'REPLACE']:
        return "args error"
    tmpEncryptKey = triple_des_encrypt(gSDEK, DES.MODE_ECB, None, gNEWKEY)
    tmpKeyCheckValue = triple_des_encrypt(gNEWKEY, DES.MODE_ECB, None, unhexlify('00' * 8))
    tmpKeyCheckValue = tmpKeyCheckValue[0:3]
    tmpKeyData = "80" + "10" + \
            hexlify(tmpEncryptKey) + \
            "03" + \
            hexlify(tmpKeyCheckValue)
    tmpAPDU = "84" + "D8"
    if tmpMode == "ADD":
        tmpAPDU += "00"
    elif tmpMode == "REPLACE":
        tmpAPDU += getKeyversion()
    else:
        return "args error"
    tmpAPDU += "81" + "4B"
    tmpAPDU += hexKeyVersion(gNEWKEYVERSION)
    tmpAPDU += tmpKeyData * 3
    tmpCMAC = retailMac(gSMAC, gSMACIV, unhexlify(tmpAPDU))
    gSMACIV = des_encrypt(gSMAC[0:8], DES3.MODE_ECB, None, tmpCMAC)
    tmpAPDU += hexlify(tmpCMAC)
    return jsonify(apdu=tmpAPDU, cmaciv=hexlify(gSMACIV))

def retailMac(key, iv, data):
    paddingSize = 8 - (len(data) % 8)
    if paddingSize > 0:
        data = hexlify(data) + '80' + '00' * (paddingSize - 1)
    data = unhexlify(data)
    des = DES.new(key[0:8], DES.MODE_CBC, iv)
    res = des.encrypt(data)
    lastblock = res[-8:]
    des = DES.new(key[8:16], DES.MODE_ECB)
    lastblock = des.decrypt(lastblock)
    des = DES.new(key[0:8], DES.MODE_ECB)
    return des.encrypt(lastblock)

def des_encrypt(key, mode, iv, data):
    if iv is None:
        des = DES.new(key, mode)
    else:
        des = DES.new(key, mode, iv)
    return des.encrypt(data)

def triple_des_encrypt(key, mode, iv, data):
    if iv is None:
        des = DES3.new(key, mode)
    else:
        des = DES3.new(key, mode, iv)
    return des.encrypt(data)

def triple_des_decrypt(key, mode, iv, data):
    if iv is None:
        des = DES3.new(key, mode)
    else:
        des = DES3.new(key, mode, iv)
    return des.decrypt(data)

@app.route('/tsm/triple-des-enc', methods=['GET'])
def triple_des_enc():
    tmpdata = request.args.get('data', None)
    if tmpdata is None:
        return "args error"
    tmpdata = unhexlify(tmpdata)
    tmpkey = request.args.get('key', None)
    if tmpkey is None:
        tmpkey = KEY_ENC
    else:
        print tmpkey
        tmpkey = unhexlify(tmpkey)
    tmpmode = request.args.get('mode', 'EBC').upper()
    if tmpmode.upper() == 'ECB':
        tmpmode = DES3.MODE_ECB
        tmpiv = None
    else:
        tmpmode = DES3.MODE_CBC
        tmpiv = request.args.get('iv', unhexlify("0000000000000000"))
    tmpcipher = triple_des_encrypt(tmpkey, tmpmode, tmpiv, tmpdata)
    return tmpcipher.encode('hex')

