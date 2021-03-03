
'''

Date: 021/15/2021
Authors: Nicholas Glass & Tyler Hammerschmidt

SLCM is a login credential management module.
'''

import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def getusername_paswd():
    '''
    Author: Nicholas Glass
    Inputs:
    Outputs: Returns valid username and password entered by a user
    '''
    #function logic
    username=input("Enter your username: <Enter your email address>")
    validboth=False
    #validate username variable
    regex = r'^[a-z0-9]+[\._]*[a-z0-9]*[@]\w+[.]\w{2,3}$'

    import re
    uvalid=False
    if re.search(regex,username):
        uvalid=True
    while uvalid==False:
        username = input("Enter your username: <Enter your email address>")
        if re.search(regex, username):
            uvalid = True
        else:
            uvalid=False

    #validate password
    password = input("Enter your password, must have 8 characters,"
                     "with at least one alphabet, one digit"
                     "and a character from [#,$,%,*]\n"
                     "\n 1. at least 8 characters, "
                     "\n 2. has at least one alphabet,"
                     "\n 3. has at least one digit, "
                     "\n 4. has at a character in {#,$,%,*}"
                     "\n Enter your password:")


         #validate password variable
    regex2 = r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)'
    pvalid = False
    if re.search(regex2,password):
        pvalid=True
    while pvalid==False:
        password = input("Enter your password, must have 8 characters,"
                         "with at least one alphabet, one digit"
                         "and a character from [#,$,%,*]\n"
                         "\n 1. at least 8 characters, "
                         "\n 2. has at least one alphabet,"
                         "\n 3. has at least one digit, "
                         "\n 4. has at a character in {#,$,%,*}"
                         "\n Enter your password:")
        if re.search(regex2,password):
            pvalid=False
        else:
            pvalid=True
    return username, password


def secure_store(username, password):
    '''
    Author: Tyler Hammerschmidt
    Inputs:
    Outputs:
    :return:
    '''


    outputfile="credential.dat"
    fd = open(outputfile,'w+')

    #encrypt password with AES algorithm
    data = b"secret"
    password = bytes("mypassword$", 'utf-8')
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(password, AES.block_size))

    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    encrypted_password=''
    #store username and encypted password in the file.
    fd.write(username+" , "+ct)
    #display message.


    print("username and password saved in ", outputfile)

def main():
    vusername,vpassword=getusername_paswd() #get valid username and password
    print("Validated username")
    print("Validated password")
    if vusername and vpassword:
        secure_store(vusername, vpassword)
    else:
        print("username and password saved failed.")

#invoke main()
main()