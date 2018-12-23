#!/usr/bin/python2

# This script has been modified a few times during the CTF so I will add here the solves from which I inspired when modifying it :)
# @terjanq @mr96 @Tom'
# Thanks to all that tried this challenge and hope you enjoyed it :)

from __future__ import print_function
import sys, time
from Crypto.Util.number import *
from pwn import *
from sage.all import gcd
from math import log

# We know the default e for RSA.generate is 65537
e = 65537

def lowest_divisor(x):
    for i in range(2, int(log(x, 2))):
        if x % i == 0:
            return i


# Connect to server and get encrypted flag
r = remote(sys.argv[1], sys.argv[2])
r.recvuntil('Galf - ')
flag_enc = int(r.recvline().strip(), 16)
r.recv()

print('[+] Encrypted flag: ' + str(flag_enc))

# Stage 1. Recover N

print('[!] Getting n...')

#n       = 0
#kns     = []
#letters = []
#letter  = 97
#found   = False
#
#while not found:
#    r.sendline('1')
#    r.recv()
#    r.sendline(chr(letter))
#    r.recvuntil('Encrypted: ')
#    kns.append(int(r.recvline().strip()))
#    r.recv()
#
#    letters.append(letter)
#    letter += 1
#
#    for i in range(len(kns)):
#        for j in range(i + 1, len(kns)):
#            n = gcd(letters[i] ** e - kns[i], letters[j] ** e - kns[j])
#            if len(bin(n)[2:]) == 1024:
#                found = True
#

r.sendline('2')
r.recv()
r.sendline('-1')
r.recvuntil('Decrypted: ')
n = int(r.recvline().strip()) + 1
r.recv()

print('[+] Found n: ' + str(n))

# Old and UGLY way of doing it

# Stage 2. Brute force bit length of flag and decrypt

#print()
#for bit_len in range(100, 1024):
#    T = getPrime(bit_len)
#
#    if bit_len % 5 == 0:
#        print('[!] Current bit length: ' + str(bit_len), end='\b' * 30)
#
#    r.sendline('2')
#    r.recv()
#    r.sendline(str((pow(T, e, n) * flag_enc) % n))
#    flag = r.recv()
#    if 'no' in flag:
#        continue
#
#    flag = int(flag.strip().split(': ')[1].split()[0])
#    flag = long_to_bytes((flag + n) // T)
#
#    if flag.startswith('X-MAS{'):
#        print('[+] Found flag: ' + flag)
#        print('[!] T bit length: ' + str(bit_len))
#        break
#
#else:
#    print('Try again...')
#

# Still old but better way

# Stage 2. find the lowest divisor of the flag and multiply D(flag/d) and D(d) to get the flag

#r.sendline('2')
#r.recv()

#d = lowest_divisor(flag_enc)
#r.sendline(str(d))
#r.recvuntil(': ')
#d_dec = int(r.recvline().strip())
#r.recv()

#r.sendline('2')
#r.recv()

#r.sendline(str(flag_enc // d))
#r.recvuntil(': ')
#flag_dec = int(r.recvline().strip())
#r.recv()

#flag = (flag_dec * d_dec) % n


# Intended way, love this <3

# Stage 2. divide the encrypted flag by 2 then multiply the decryption by 2
# In modular arithmetics to divide by x is the same as multiplying by it's inverse (took me a while to realize, but blew my mind)

r.sendline('2')
r.recv()

r.sendline(str(flag_enc * pow(inverse(2, n), e, n)))
r.recvuntil(': ')
flag = (int(r.recvline().strip()) * 2) % n
r.recv()

print('[+] Flag: ' + long_to_bytes(flag).decode())

r.sendline('3')
r.close()
