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
		self.client = ("127.0.0.1", 4445)
		self.bufferSize  = 2048
	
	def keyExchange(self,listener):
		dh = DH.DeffyHelman()
		peer1A = dh.calValue(277)
		#Peer1 sending its A value of DH 
		listener.sendto(bytes(str(peer1A),'utf-8'), self.client)
	
		#Now Receiving peer2 B Value
		peer2B=listener.recv(self.bufferSize)#receiving peer2 
		peer2B = removecharacters(peer2B)	
		#Calculating Secret
		dh.calSecret(int(peer2B),277)
		#Sending Secret xor with aes key

		self.obj = aes.AES()
		self.key = self.obj.getInitialKey()
			
		key = ''

		for k1 in self.key:
			for k2 in k1:
				key += k2
		key = int(key,16)
		listener.sendto(bytes(str(dh.SendSecret(key)),'utf-8'), self.client)
	
	def message(self,listener):
		choose = 1
		while choose == 1 or choose == 2:
			self.obj = aes.AES(self.key)
			choose = input("Press 1 to recieve message, 2 to send message and else 0 to end communication: ")
			choose = int(choose)
			
			listener.sendto(bytes(str(choose),'utf-8'), self.client)
			
			if choose == 2:
				self.AESencryption(listener)
			elif choose == 1:
				self.AESdecryption(listener)
				
	def AESdecryption(self,listener):
		encryptText = listener.recv(self.bufferSize)
		encryptText = removecharacters(encryptText)
	
		encryptText = [encryptText[ind:ind + 2] for ind in range(0,len(encryptText),2)]
		encryptText = [list(encryptText[ind:ind + 16]) for ind in range(0,len(encryptText),16)]
	
		self.obj.decryption(encryptText)
					
	def AESencryption(self,listener):
		plainText = input("Enter plainText: ")
		self.obj.electronicCodebookBook(plainText)
		cT = self.obj.encryption()
		listener.sendto(bytes(str(cT),'utf-8'), self.client)
 
if __name__ == "__main__":
	localIP     = "127.0.0.1"
	localPort   = 4446

	# Create a datagram socket
	Listener = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
	# Bind to address and ip
	Listener.bind((localIP, localPort))
	
	com = Communication()
	com.keyExchange(Listener)
	com.message(Listener)