import socket
import aes
import DH

def removecharacters(username):
	usernames = list(str(username))
	usernames[0]=''
	usernames[1]=''
	usernames[-1]=''

	''.join(usernames)
	user=""
	for x in usernames:
		user+=x

	return user

class Communication:
	def __init__(self):
		self.key = []
		self.obj = 0
		self.client = ("127.0.0.1", 4446)
		self.bufferSize  = 2048
	
	def keyExchange(self,c):
		dh = DH.DeffyHelman()	
		#Receiving peer1 A Value
		peer1A=c.recv(self.bufferSize)
		peer1A = removecharacters(peer1A)
	
		#peer2 sending its B value to peer1
		c.sendto(bytes(str(dh.calValue(95)),'utf-8'), self.client)
	
		#Calculating Secret
		dh.calSecret(int(peer1A),95)
	
		Secret=c.recv(self.bufferSize)
		Secret = removecharacters(Secret)
	
		aesKey = format(dh.calKey(int(Secret)),'02x')
	
		aesKey = [aesKey[ind:ind + 2] for ind in range(0,len(aesKey),2)]
		aesKey = [list(aesKey[ind:ind + 4]) for ind in range(0,len(aesKey),4)]
			
		self.key = aesKey
		
	def message(self,c):
		choose = 1
		while choose == 1 or choose == 2:
			self.obj = aes.AES(self.key)
			choose = c.recv(self.bufferSize)
			choose = int(removecharacters(choose))
	
			if choose == 2:
				self.AESdecryption(c)
			elif choose == 1:
				self.AESencryption(c)
				
	def AESdecryption(self,c):
		encryptText = c.recv(self.bufferSize)
		encryptText = removecharacters(encryptText)
	
		encryptText = [encryptText[ind:ind + 2] for ind in range(0,len(encryptText),2)]
		encryptText = [list(encryptText[ind:ind + 16]) for ind in range(0,len(encryptText),16)]
	
		self.obj.decryption(encryptText)
	
	def AESencryption(self,c):
		plainText = input("Enter plainText: ")
		self.obj.electronicCodebookBook(plainText)

		cT = self.obj.encryption()
		c.sendto(bytes(str(cT),'utf-8'), self.client)

if __name__ == "__main__":
	localIP     = "127.0.0.1"
	localPort   = 4445

	# Create a datagram socket
	Listener = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
	# Bind to address and ip
	Listener.bind((localIP, localPort))

	com = Communication()
	com.keyExchange(Listener)
	com.message(Listener)