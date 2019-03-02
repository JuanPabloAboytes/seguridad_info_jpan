##Read first the file "LEER PRIMERO"
################################

############### INICIO    MD5        #########
import hashlib
from Crypto.Hash import MD5
from time import time
tiempo_inicial = time()

f=open("ocho.txt","r")
print('\n'+ "--------MD5---------" + '\n')
x=0
for x in range(30):
    m = MD5.new()
    mes=f.readline()
    c=mes
    b = c.rstrip('\n')
    m.update(b)
    tiempo_final = time() 
    tiempo_ejecucion = tiempo_final - tiempo_inicial
    #print m.hexdigest()
    #print x+1
    print "El tiempo de ejecucion fue:",tiempo_ejecucion 
    
############### FIN    MD5        #########


############### INICIO    SHA1        #########

from Crypto.Hash import SHA
tiempo_inicial = time()
f=open("SHA1.txt","r")
print('\n'+ "--------SHA1---------" + '\n')
x=0
for x in range(30):
    m = SHA.new()
    mes=f.readline()
    c=mes
    b = c.rstrip('\n')
    m.update(b)
    tiempo_final = time() 
    tiempo_ejecucion = tiempo_final - tiempo_inicial
    #print m.hexdigest()
    #print x+1
    print "El tiempo de ejecucion fue:",tiempo_ejecucion

###############      FIN    SHA1        #########



#######           INICIO      SHA256    ############

from Crypto.Hash import SHA256
tiempo_inicial = time()
f=open("SHA2.txt","r")
print('\n'+ "--------SHA2---------" + '\n')
x=0
for x in range(30):
    m = SHA256.new()
    mes=f.readline()
    c=mes
    b = c.rstrip('\n')
    m.update(b)
    tiempo_final = time() 
    tiempo_ejecucion = tiempo_final - tiempo_inicial
    #print m.hexdigest()
    #print x+1
    print "El tiempo de ejecucion fue:",tiempo_ejecucion

###############      FIN    SHA256        #########



###############      INICIO    DES        #########

from Crypto.Cipher import DES3
from Crypto import Random
from Crypto.Util import Counter
print('\n'+ "--------DES---------" + '\n')
tiempo_inicial = time()
f=open("DES.txt","r")
x=0
for x in range(30):
    key = str.encode(f.readline()[0:16])
    DES3.adjust_key_parity(key)
    cipher = DES3.new(key, DES3.MODE_EAX)
    msg = cipher.nonce + cipher.encrypt(str.encode(f.readline()))
    tiempo_final = time() 
    tiempo_ejecucion = tiempo_final - tiempo_inicial
    print "El tiempo de ejecucion fue:",tiempo_ejecucion
    
###############      FIN    DES        #########


###############      INICIO    AES        #########

from Crypto.Cipher import AES
print('\n'+ "--------AES---------" + '\n')
tiempo_inicial = time()
f=open("AES.txt","r")
x=0
for x in range(30):
    key = str.encode(f.readline()[0:32])
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext=cipher.encrypt(str.encode(f.readline()))
    tiempo_final = time() 
    tiempo_ejecucion = tiempo_final - tiempo_inicial
    print "El tiempo de ejecucion fue:",tiempo_ejecucion
    
    
############### FIN    AES        #########


###############      INICIO    OAEP        #########

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
print('\n'+ "--------OAEP---------" + '\n')
tiempo_inicial = time()
f=open("RSAOEAP.txt","r")
x=0
for x in range(10):
    tupkey=(int(f.readline(),16),int(f.readline(),16),int(f.readline(),16),int(f.readline(),16),int(f.readline(),16))
    key = RSA.construct(tupkey)
    cipher_rsa = PKCS1_OAEP.new(key)
    a=cipher_rsa.encrypt(b'RSAOEAP')
    tiempo_final = time() 
    tiempo_ejecucion = tiempo_final - tiempo_inicial
    print "El tiempo de ejecucion fue:",tiempo_ejecucion

###############      FIN    OAEP        #########


#####     INICIO   DSA             ######

from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS
print('\n'+ "--------DSA---------" + '\n')
tiempo_inicial = time()
f=open("CTR_public.txt","r")
for x in range(10):
    tupkey=(int (f.readline(),16),int (f.readline(),16),int (f.readline(),16),int(f.readline(),16),int(f.readline(),16))
    key = DSA.construct(tupkey)
    signer = DSS.new(key, 'fips-186-3')
    h = SHA256.new(str.encode(f.readline()))
    a=signer.sign(h)
    tiempo_final = time() 
    tiempo_ejecucion = tiempo_final - tiempo_inicial
    print "El tiempo de ejecucion fue:",tiempo_ejecucion
    
    
#####     FIN   DSA             ######

####   INICIO RSA-PSS  #####  
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

print('\n'+ "--------RSA-PSS---------" + '\n')
tiempo_inicial = time()
f=open("RSAOEAP.txt","r")
message = '0000000000000000000000000000000000000000'
times = list()
for x in range(10):
    t_start = time()
    tupkey = (int(f.readline(),16),int(f.readline(),16),int(f.readline(),16),int(f.readline(),16),int(f.readline(),16))
    key = RSA.construct(tupkey)
    h = SHA256.new(message)
    signature = pss.new(key).sign(h)
    verifier = pss.new(key)
    tiempo_final = time() 
    tiempo_ejecucion = tiempo_final - tiempo_inicial
    print "El tiempo de ejecucion fue:",tiempo_ejecucion

