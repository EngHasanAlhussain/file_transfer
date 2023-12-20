#file transfer application#

import hashlib
import socket                   # Import socket module
from Crypto import Random
from Crypto.Cipher import AES
import secrets
import os

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


#Setting up the private and public key for Alice
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

#Alice private key d
d1=modinv(e1,p_q_neg1)

#d1=d1-3
#this change is used to pose Trudy as Alice

#set diffie hellman g & m

g1=2
m1="FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF".encode()
m1=int(m1, 16)
g2=2
m2="FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF".encode()
m2=int(m2, 16)

#Initilize a & Ra as random bits

a=secrets.randbits(2048)
Ra=secrets.randbits(256)

g_a_mod_m=power_mod(g1,a,m1)

#we have set all what is needed to start authentication
#Now start connection and authentication

######################################################
##Start connection the same as phase 1               #
######################################################

s = socket.socket()             # Create a socket object
host = "192.168.100.6"  # Set the IP-address for the server
#host = "192.168.43.61"
port = 5050                    # Reserve a port for your service.

#key = '7f31574e25261f2e5bc20bff94c4f028' this is the key that was used in phase 2, now it is replaced

s.connect((host, port))     #Connect host & port

#####################################################
#####################################################

# Authentication starts (phase_3 part)#
#send Ra,g_a_mod_m as stated in the protocol

s.send(str(Ra).encode())
s.send(str(g_a_mod_m).encode())

Rb = s.recv(1024 * 1024)  # recv. Rb
Rb=int(Rb)

g_b_mod_m = s.recv(1024 * 1024)  # recv. Rb
g_b_mod_m=int(g_b_mod_m)

SB = s.recv(1024 * 1024)  # recv. Rb
SB=int(SB)

########################################################
############End of step 2##############################
########################################################

#compute g_ab mod m to calculate the key
g_ab_mod_m=power_mod(g_b_mod_m,a,m2)

#########compute H################
H=Alice+Bob+str(Ra)+str(Rb)+str(g_a_mod_m)+str(g_b_mod_m)+str(g_ab_mod_m)
h = hashlib.sha256()
h.update(H.encode())
H=h.hexdigest()
H=str(H)
####################
SB_unsigned=power_mod(SB,e2,N2) #Unsign SB

#print Ra, a for each session
print("Ra : ",Ra)
print(" a : ",a)

#extract H from Bob's SB

H_B=SB_unsigned-int(Bob)
H_B=str(hex(H_B))
H_B=H_B[2:len(H_B)-1]

#If H matches H sent from Bob, then
#Bob is authenticated to Alice, send flag 1
# otherwise, Bob is not authenticated to Alice
#send a flag 0 and terminate the session

if H==H_B:
	print("Bob is authenticated to Alice")
	s.send("1".encode())
	#Go forward to step 3
else:
	print("Bob is not authenticated to Alice")
	print("The connection is terminated")
	s.send("0".encode())
	exit(0)
########################################################
############################ step 3 #######################
########################################################

del a   #delet a

#combine SA with Alice
#this will be encrypted using K
#and sent to Bob as E(SA,Alice,K)

SA_combined=H+Alice
SA=power_mod(int(SA_combined,16),d1,N1)

#compute the key

K = hashlib.sha256(str(g_ab_mod_m).encode())
K=str(K.hexdigest())
K=K[0:32]

SA_Alice=str(SA)+str(Alice)

IV = secrets.token_hex(8) # generate IV
cipher = AES.new(K.encode(), AES.MODE_CBC, str(IV).encode())     #Encryption object using AES
third_message = cipher.encrypt(pad(SA_Alice).encode())        #encrypt
s.send(third_message)
s.send(IV.encode())

flag=s.recv(10)

#we check if bob did authenticate Alice or not
# if the flag is 0, then Alice is not authenticated to Bob
#Otherwise, the authentication is seccussful
#Then we can share files as done in phase 2
#but this time using the key established

if flag.decode()=="0":
	print("Alice is not authenticated to Bob")
	print("the session is terminated")
	exit(0)
key=K

choice=0
print("Hello, this is a client-server transfer file application")
print("You are connecting to server :",host,)
while True:
	choice = input("\n please choose one of the following: \n1.GET \n2.PUT\n3.QUIET \n") #Let the user choose, get, put, quiet
	if choice == "1":    #get choice
		new_file = input("enter the file name to receive \n") #ask the user to enter file name
		s.send(choice.encode())                             #send the choice 1 to the server, so it set up to send the file
		s.send(new_file.encode())                          #send the file name to be received
		print("connected...")
		filename = new_file
		file = open(filename, 'wb')             #open a file, so the received data from the server will be written to it

		print('receiving data...')

		########
		IV=s.recv(1024 * 1024) #recv. IV
		print("IV : ",IV)
		data = s.recv(1024 * 1024)  # reveivce data
		print("cipher : ",data)
		#############################################
		#decrypting the cipher text after receiving
		#####################################
		cc=AES.new(key.encode(),AES.MODE_CBC,IV)
		data=cc.decrypt(data).decode("utf-8")
		c=data.count("{")
		data=data[:len(data)-c]
		data=data[2:len(data)-1]
		print("Decrypted : ",data)
		########
		file.write(bytes(data.encode()))              #write data to the file
		file.close()                  #close the file
		print('Successfully get the file')
	if choice == "2":
		s.send(choice.encode())      #choice put(2)
		filename = input("enter the file name to be sent \n")   #ask the user to enter the file that will be taken from the server
		s.send(filename.encode())               #send the file name
		f = open(filename, 'rb')                #open the file to read the data that will be sent to the server
		print("sending the file")
		l = f.read()         #read data
		f.close()                     #close the file

		print("Plaintext : ",l)
		print("Plaintext in hex: ",l.hex())
		IV = secrets.token_bytes(16)         #generate IV
		print("IV : ",IV)
		print("IV in hex",IV.hex())
		message = l                    #message to be encrypted
		print("key in hex",key.encode().hex())
		cipher = AES.new(key.encode(), AES.MODE_CBC, IV)     #Encryption object using AES
		print("message in hex",l.hex())
		GG = cipher.encrypt(pad(l).encode())        #encrypt
		print("cipher in hex : ",GG.hex())
		print("cipher : ",GG)
		s.sendall(IV)                      #send IV
		Dummy=1+3
		Dummy=Dummy-1
		s.sendall(GG)                     #send cipher text
		print("The file was sent Successfully")
	if choice == "3":
		new_file = ""
		s.send(choice.encode())    #choice 3, terminate
		s.send(new_file.encode())
		print("Thank you for using the program")
		break

print("Key : ",K)

del K #delete the key
del key

s.close()   #connection closed
print('connection closed')
