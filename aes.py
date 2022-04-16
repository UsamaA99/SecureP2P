#Muhammad Usama Azam
#AES 128-bit with ECB Mode

import collections
import math

S_Box = "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0 b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75 09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2 cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08 ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16".split()

S_Box = [list(S_Box[ind:ind + 16]) for ind in range(0,len(S_Box),16)]

Inverse_S_Box = "52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb 54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e 08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25 72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92 6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84 90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06 d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b 3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73 96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e 47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4 1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f 60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61 17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d".split()

Inverse_S_Box = [list(Inverse_S_Box[ind:ind + 16]) for ind in range(0,len(Inverse_S_Box),16)]

class generateKeys:
	def __init__(self, initialKey):
		self.key = initialKey
		self.prkey = self.key				#To store previous round key but for round 0 it will be same
		self.roundConstants = ['01','02','04','08','10','20','40','80','1B','36']
		self.roundIndex = 0
	
	def circularByteLeftShift(self,gW):
		gW = collections.deque(gW)
		gW.rotate(-1)				# shift gW one place to left
		return list(gW)
		
	def byteSubstitution(self,gW):
		i = 0
		for byte in gW:
			gW[i] = S_Box[int(byte[0],16)][int(byte[1],16)]		
			i += 1
		return gW
		
	def addRoundConstant(self,gW):
		MSB = hex(int(gW[0][0],16) ^ int(self.roundConstants[self.roundIndex][0],16))	
		LSB = hex(int(gW[0][1],16) ^ int(self.roundConstants[self.roundIndex][1],16))	
	
		gW[0] = MSB[2] + LSB[2]
		return gW
		
	def galoisFunc(self):
		gW = self.prkey[3]		# To get g(w(3)) from a 2D list key in case of round 0
		gW = self.circularByteLeftShift(gW)
		gW = self.byteSubstitution(gW)	
		gW = self.addRoundConstant(gW)
		return gW
	
	def genRoundKey(self,gW):
		gW1 = []
		for i in range(0,len(gW)):
			gW1.append(format(int(gW[i],16) ^ int(self.prkey[0][i],16),'02x'))
		
		gW2 = []
		for i in range(0,len(gW)):
			gW2.append(format(int(gW1[i],16) ^ int(self.prkey[1][i],16),'02x'))
		
		gW3 = []
		for i in range(0,len(gW)):
			gW3.append(format(int(gW2[i],16) ^ int(self.prkey[2][i],16),'02x'))
		
		gW4 = []
		for i in range(0,len(gW)):
			gW4.append(format(int(gW3[i],16) ^ int(self.prkey[3][i],16),'02x'))
		
		roundKey = gW1 + gW2 + gW3 + gW4
		
		self.prkey = [list(roundKey[ind:ind+4]) for ind in range(0,len(roundKey),4)]
		self.roundIndex += 1
		return roundKey
				
class encryptPT:
	def __init__(self, plainText):
		self.pT = plainText
		self.stateMat = []
		self.mxcol = [['02','03','01','01'],['01','02','03','01'],['01','01','02','03'],['03','01','01','02']]
	
	def keyWhitening(self, k):
		for i in range(0,len(k)):
			for j in range(0,len(k[i])):
				self.stateMat.append(format(int(k[i][j],16) ^ int(self.pT[i][j],16),"02x"))
		
	def matrixTranspose(self, mat):
		stMatTranspose = [[],[],[],[]]
		j = 0
		for i in range(0,len(mat)):
			stMatTranspose[j].append(mat[i])
			j += 1
			if j == 4:
				j = 0
		return stMatTranspose
		
	def substituteByte(self):
		i = 0
		for byte in self.stateMat:
			self.stateMat[i] = S_Box[int(byte[0],16)][int(byte[1],16)]		
			i += 1
		
	def shiftRows(self):
		self.stateMat = self.matrixTranspose(self.stateMat)
		
		i = 0
		j = 0 
		for row in self.stateMat:
			row = collections.deque(row)
			row.rotate(i)
			i -= 1
			self.stateMat[j] = list(row)
			j += 1
		
		mat = []
		for lt in self.stateMat:
			for item in lt:
				mat.append(item)
		self.stateMat = self.matrixTranspose(mat)
		
	def mixColumns(self):
		result = [[],[],[],[]]
		newMat = []
		
		for i in range(0,len(self.mxcol)):
			l = 0
			for j in range(0,len(self.stateMat)):
				for k in range(0,len(self.stateMat[j])):
					if self.mxcol[i][k] == '03':
						result[l] = hex((int('02',16) * int(self.stateMat[j][k],16)) ^ int(self.stateMat[j][k],16)) 
					else:
						result[l] = hex(int(self.mxcol[i][k],16) * int(self.stateMat[j][k],16))
					if int(self.stateMat[j][k],16) >= int('80',16) and int(self.mxcol[i][k],16) >= int('02',16):		# checking if MSB greater then 8 and Shift 2 occurs then overflow will come
						result[l] = format(int(result[l],16),'x')
						result[l] = result[l][1] + result[l][2]
						result[l] = hex(int(result[l],16) ^ int('1b',16))
					l += 1
				val = format(int(result[0],16) ^ int(result[1],16) ^ int(result[2],16) ^ int(result[3],16),'02x')
				newMat.append(val)
				l = 0
		self.stateMat = newMat
		
	def addRoundKey(self, rk):	
		self.stateMat = self.matrixTranspose(self.stateMat)
		
		mat = []
		for lt in self.stateMat:
			for item in lt:
				mat.append(item)
		self.stateMat = mat
		
		for i in range(0,len(self.stateMat)):
			self.stateMat[i] = format(int(self.stateMat[i],16) ^ int(rk[i],16),"02x")
			
	def encryptionRound(self, roundKey):
		self.substituteByte()
		self.shiftRows()
		self.mixColumns()
		self.addRoundKey(roundKey)
		return self.stateMat
	
	def lastRound(self,roundKey):
		self.substituteByte()
		self.shiftRows()
		
		mat = []
		for lt in self.stateMat:
			for item in lt:
				mat.append(item)
		self.stateMat = mat
		
		for i in range(0,len(self.stateMat)):
			self.stateMat[i] = format(int(self.stateMat[i],16) ^ int(roundKey[i],16),"02x")
		return self.stateMat

class decrypt:
	def __init__(self, cipherText):
		self.cTMat = cipherText
		self.inversemxcol = [['0e','0b','0d','09'],['09','0e','0b','0d'],['0d','09','0e','0b'],['0b','0d','09','0e']]
	
	def reverseKeyWhitening(self,k):
		for i in range(0,len(self.cTMat)):
			self.cTMat[i] = format(int(self.cTMat[i],16) ^ int(k[i],16),"02x")
		
	def matrixTranspose(self, mat):
		cTMatTranspose = [[],[],[],[]]
		j = 0
		for i in range(0,len(mat)):
			cTMatTranspose[j].append(mat[i])
			j += 1
			if j == 4:
				j = 0
		return cTMatTranspose
	
	def convert(self):
		mat = []
		for lt in self.cTMat:
			for item in lt:
				mat.append(item)
		return mat
	
	def inverseShiftRows(self):
		self.cTMat = self.matrixTranspose(self.cTMat)
		
		i = 0
		for row in self.cTMat:
			row = collections.deque(row)
			row.rotate(i)
			self.cTMat[i] = list(row)
			i += 1
	
		self.cTMat = self.matrixTranspose(self.convert())	
		self.cTMat = self.convert()
		
	def inverseSubstituteByte(self):
		i = 0
		for byte in self.cTMat:
			self.cTMat[i] = Inverse_S_Box[int(byte[0],16)][int(byte[1],16)]		
			i += 1 
		
	def addRKey(self,k):
		for i in range(0,len(self.cTMat)):
			self.cTMat[i] = format(int(self.cTMat[i],16) ^ int(k[i],16),"02x")
		
	def inverseMixColum(self):
		self.cTMat = [list(self.cTMat[ind:ind + 4]) for ind in range(0,len(self.cTMat),4)]		
		
		result = [[],[],[],[]]
		newMat = []
		dict1 = {'09':3,'0b':2,'0d':1,'0e':1}
		dict2 = {'09':0,'0b':1,'0d':2,'0e':1}
		
		for i in range(0,len(self.cTMat)):
			l = 0
			for j in range(0,len(self.cTMat)):
				for k in range(0,len(self.cTMat[j])):
					loopvar = dict1[self.inversemxcol[i][k]]
					temp = self.cTMat[j][k]
					for x in range(loopvar):
						result[l] = format(int('02',16) * int(temp,16),'02x')
						if int(temp[0],16) >= int('8',16):
							result[l] = result[l][1] + result[l][2] 
							result[l] = format(int(result[l],16) ^ int('1b',16),'02x')
						temp = result[l]
					temp = format(int(temp,16) ^ int(self.cTMat[j][k],16),'02x')	
					
					loopvar2 = dict2[self.inversemxcol[i][k]]
					for y in range(loopvar2):
						result[l] = format(int('02',16) * int(temp,16),'02x')
						if int(temp[0],16) >= int('8',16):
							result[l] = result[l][1] + result[l][2] 
							result[l] = format(int(result[l],16) ^ int('1b',16),'02x')
						temp = result[l]
					if self.inversemxcol[i][k] != '09':
						temp = format(int(temp,16) ^ int(self.cTMat[j][k],16),'02x')	
					if self.inversemxcol[i][k] == '0e':
						result[l] = format(int('02',16) * int(temp,16),'02x')
						if int(temp[0],16) >= int('8',16):
							result[l] = result[l][1] + result[l][2] 
							result[l] = format(int(result[l],16) ^ int('1b',16),'02x')
						temp = result[l]
					result[l] = temp
					l += 1
				val = format(int(result[0],16) ^ int(result[1],16) ^ int(result[2],16) ^ int(result[3],16),'02x')
				newMat.append(val)
				l = 0
		
		self.cTMat = self.matrixTranspose(newMat)
		self.cTMat = self.convert()
							
	def decryptionRound(self, roundKey):
		self.inverseShiftRows()
		self.inverseSubstituteByte()
		self.addRKey(roundKey)
		self.inverseMixColum()
		return self.cTMat
	
	def lastRound(self, roundKey):
		self.inverseShiftRows()
		self.inverseSubstituteByte()
		rK = []
		for lt in roundKey:
			for item in lt:
				rK.append(item)
		self.addRKey(rK)
		return self.cTMat
		
class AES(generateKeys, encryptPT, decrypt):
	def __init__(self, initKey = 0):
		self.cipherText = []
		self.cTBlocks = []
		self.plainText = []
		self.pTBlocks = []
		self.roundKeys = []
		if initKey == 0:
			self.initialKey = self.takeInitialKey()
		else:
			self.initialKey = initKey
		generateKeys.__init__(self,self.initialKey)
		self.generateRoundKeys()
	
	def takeInitialKey(self):
		key = ""
		while(len(key) != 16):
    			print("!Please Input Key as 16 chars!")
    			key = input("Enter Key:")
		return self.convertIntoHexa(key)
	
	def getInitialKey(self):
		return self.initialKey
	
	def electronicCodebookBook(self, plainText):
		self.makepTBlocks(plainText)
	
	def encryption(self):
		cipherText = ""
		for i in range(0,len(self.pTBlocks)):
			encryptPT.__init__(self,self.pTBlocks[i])
			encryptPT.keyWhitening(self, self.initialKey)
			self.cTBlocks.append(self.createCipherText())
		
		print("Cipher Text Generated Is: ",end="")
		for cT in self.cTBlocks:
			for i in range(0,len(cT)):
				print(cT[i] + " ", end = "")
				cipherText += cT[i]

		print("")
		return cipherText
		
	def decryption(self, cTB = 0):
		if cTB != 0:
			self.cTBlocks = cTB
		plainText = ""
		print("Plain Text Generated Is: ", end = "") 
		#Decryption:
		for i in range(0,len(self.cTBlocks)):
			self.cipherText = self.cTBlocks[i]
			pT = str(bytes.fromhex("".join(self.createPlainText())).decode('utf-8'))
			print(pT, end = "")
			plainText += pT
		print("")
		return plainText
			
	def makepTBlocks(self, plainText):
		inputBlocks = math.ceil(len(plainText) / 16);
		pTPadding = inputBlocks * 16;
		pTPadding = pTPadding - len(plainText)
		plainText += '\0' * pTPadding
		
		start,end = 0,16
		
		for i in range(0,inputBlocks):
			self.pTBlocks.append(self.convertIntoHexa(plainText,start,end))
			start,end = end,end+16
		
	def convertIntoHexa(self, value, start = 0, end = 16):
		value = [list(value[ind:ind + 4]) for ind in range(start,end,4)]		# will create a 2D list of each item of 4 chars

		i,j = 0,0

		for l in value:
			for char in l:
				char = format(ord(char),"x")
				value[i][j] = char
				j += 1
			i += 1
			j = 0
		return value
	
	def generateRoundKeys(self):
		for i in range(0,10):
			self.roundKeys.append(generateKeys.genRoundKey(self, generateKeys.galoisFunc(self)))
		
	def createCipherText(self):
		for i in range(0,9):
			encryptPT.encryptionRound(self, self.roundKeys[i])
		self.cipherText = encryptPT.lastRound(self, self.roundKeys[9])
		return self.cipherText
		
	def createPlainText(self):
		decrypt.__init__(self,self.cipherText)
		decrypt.reverseKeyWhitening(self, self.roundKeys[9])
		
		for i in range(2,11):
			decrypt.decryptionRound(self, self.roundKeys[-i])
		self.plainText = decrypt.lastRound(self, self.initialKey)
		return self.plainText
