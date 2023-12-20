#file transfer application#


import socket                   # Import socket module
import secrets
import math
from Crypto import Random
from Crypto.Cipher import AES
import hashlib

#Padding method

def pad(P):
  P=str(P)
  pad = P + ((16 - len(P) % 16)*'{')
  return pad

#power mod to do repeated squaring

def power_mod(b, e, m):
    " Without using builtin function "
    x = 1
    while e > 0:
        b, e, x = (
            b * b % m,
            e // 2,
            b * x % m if e % 2 else x
        )

    return x


#gcd method

def gcd(p,q):
# Create the gcd of two positive integers.
    while q != 0:
        p, q = q, p%q
    return p

#Is prime method

def is_coprime(x, y):
    return gcd(x, y) == 1

#egcd method

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

#mod inverse method

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

#Alice & Bob IDs

Alice="1"
Bob="0"

#Setting up the private and public key for Bob
#the public key (e,N) is shared for both Alice & Bob
#the private key d is not shared
p1 = 3136666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666313
q1 = 3130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001183811000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313
N1=p1*q1

p2 = 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
q2 = 1357911131517193133353739515355575971737577799193959799111113115117119131133135137139151153155157159171173175177179191193195197199311313315317319331333335337339351353355357359371373375377379391393395397399511513515517519531533535537539551553555557559571573575577579591593595597599711713715717719731733735737739751753755757759771
N2=p2*q2

p_q_neg1 = (p1-1)*(q1-1)
e1=5
p_q_neg2 = (p2-1)*(q2-1)
e2=3

#Now we have (e1,N1) & (e2,N2)
#the first one for Alice, the 2nd for Bob


#Bob private key d
d2=modinv(e2,p_q_neg2)

#this change is used to pose Trudy as Bob
#d2=d2-3

#Initilize b & Rb as random bits
b=secrets.randbits(2048)
Rb=secrets.randbits(256)

#set diffie hellman g & m

g1=2
m1="FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF".encode()
m1=int(m1, 16)
g2=2
m2="FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF".encode()
m2=int(m2, 16)

g_b_mod_m=power_mod(g2,b,m2)

#we have set all what is needed to start authentication
#Now start connection and authentication

#key = '7f31574e25261f2e5bc20bff94c4f028'  this is the old key that was hardcoded, now it is not used and replaced

##############################################
#Same connection procedure in phase2
###############################################
port = 5050                    # Reserve a port for service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()    # Get local machine name
s.bind((host, port))            # Bind to the port
s.listen(5)                     # Now wait for client connection.

print('Server listening....')
conn, addr = s.accept()     # Establish connection with client.
print ('Got connection from', addr)
######################################################
#####################################################

#print Rb & b for each session
print("Rb : ",Rb)
print("b : ",b)

Ra = conn.recv(1024 * 1024)  # Receive Ra
g_a_mod_m = conn.recv(1024 * 1024)  # Receive g_a_mod_m

Ra=int(Ra)                  # convert them to integers
g_a_mod_m=int(g_a_mod_m)

conn.send(str(Rb).encode())  # send Rb
conn.send(str(g_b_mod_m).encode())  # send gb_mod_m

g_ab_mod_m=power_mod(g_a_mod_m,b,m2)         #compute g_ab mod m to calculate the key

H=Alice+Bob+str(Ra)+str(Rb)+str(g_a_mod_m)+str(g_b_mod_m)+str(g_ab_mod_m)       #compute H
h = hashlib.sha256()
h.update(H.encode())
H=h.hexdigest()
SB_combined=H+Bob        #combine H with Bob's ID to get SB
SB=power_mod(int(SB_combined,16),d2,N2)        #sign SB
conn.send(str(SB).encode())        #send signed SB

#######################################
#############step3##########################
#######################################

del b        #delet b

flag=conn.recv(10)         #receive a flag that indicate if Bib is authenticated to Alice or not

#if flag is zero, then Bob is not authenticated to Alice
#connection is terminated
if flag.decode()=="0":
    print("Bob is not authenticated to Alice")
    print("The connection is terminated")
    exit(0)

#if Bob is authenticated to Alice, then compute the key usign g_ab_mod_m

K = hashlib.sha256(str(g_ab_mod_m).encode())
K=str(K.hexdigest())
K=K[0:32]

third_message = conn.recv(1024 * 1024)  # receive the message that is E(Alice,SA,K)
ds=1 #dummy varaible
iv=conn.recv(1024*1024)       #receive IV to decryption

#    decrypt the message   #
cc = AES.new(K.encode(), AES.MODE_CBC, iv)
third_message = cc.decrypt(third_message).decode("utf-8")
c = third_message.count("{")
third_message = third_message[:len(third_message) - c]
##########################

SA_3rd=int(third_message)-int(Alice)    # this is SA but signed !

SA_3rd=str(SA_3rd)
SA_3rd=SA_3rd[:len(SA_3rd)-1]

SA_unsigned=power_mod(int(SA_3rd),e1,N1)    # this is SA without sign

H_A=SA_unsigned-int(Alice)     #this is H that is sent by Alice
H_A=str(hex(H_A))
H_A=H_A[2:len(H_A)-1]

#    #    #    #    #    #    #    #    #    #    #
#if the computed H is diffrent from H Alice       #
#Then Alice is authenticated to Bob               #
#Terminate the session, send a flag 0             #
#else Alice is authenticated to Bob, send a flag 1#
#    #    #    #    #    #    #    #    #    #    #

if H_A==H:
    print("Alice is authenticated to Bob")
    conn.send("1".encode())
else:
    print("Alice is not authenticated to Bob")
    conn.send("0".encode())
    print("the session is terminated")
    exit(0)

key=K

#After Finishing authentication,
# we can transger the files using the shared key
# and replace it by the old one in phase 2

while True:
    choice = conn.recv(1024*1024)  #Receive the choice, input, get, or quiet
    choice=int(choice)

    if choice == 3:
        break
    if choice==1:
        filename = conn.recv(1024*1024)   #If the choice is get, then retreive the file's name
        f = open(filename, 'rb')     #Open the file, using its name
        l = f.read()        #Read the file and retreive its data
        print("Plain text : ",l)
        #########################
        IV=secrets.token_bytes(16) #generate IV
        print("IV : ",IV)
        ###AES object to encrypt
        cipher=AES.new(key.encode(),AES.MODE_CBC,IV)
        GG=cipher.encrypt(pad(l).encode())
        print("encrypted text : ",GG)
        conn.send(IV)#send IV
        conn.send(GG) #send cipher text
        #########################

        f.close()
        print('Done sending')
    if choice==2:
        ########################################################
        #if the choice is put, receive a file from the client###
        ########################################################
        filename = conn.recv(1024*1024)       # receive file name
        print(filename)
        #Open a file with the same name that has the client chooses
        print('receiving data...')

        IV = conn.recv(16)
        print("IV:",IV)
        data = conn.recv(1024*1024)  # Recieve the data to write it on the opened file
        print("cipher : ", data)
        #######################c
        #cipher AES object to decrypt
        ############################
        cc = AES.new(key.encode(), AES.MODE_CBC, IV)  #
        data = cc.decrypt(data).decode("utf-8")  #
        c = data.count("{")
        data = data[:len(data) - c]
        ##########################
        data=data[2:len(data)-1]
        print("Decrypted text : ",data)
        f = open(filename, 'wb')        #Open the file to write
        f.write(bytes(data.encode()))                   # write the data on the file
        f.close()           #close the file
        print('Successfully get the file')

#Close the program if choice is 3
#Close the connection

print("Key :",K)

del K #delete the key
del key
conn.close()
print("connection has been closed")
