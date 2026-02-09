#!/usr/bin/env python3

import bcrypt
import secrets
import string
import sys

password = None

if len(sys.argv) == 2:
    password = sys.argv[1]

def genpwd():
    letters = string.ascii_letters
    digits = string.digits
    #special_chars = string.punctuation
    
    alphabet = letters + digits #+ special_chars
    
    # fix password length
    pwd_length = 24
    while True:
        pwd = ''
        for i in range(pwd_length):
            pwd += ''.join(secrets.choice(alphabet))
    
        break
    
    return (pwd)

if password is None:
    password = genpwd()

e_pwd = password.encode()
hashed = bcrypt.hashpw(e_pwd, bcrypt.gensalt())
d_hashed = hashed.decode()
sys.stdout.write(f'password: {password} hashed bcrypt password: {d_hashed}\n')
