class DeffyHelman:
	def __init__(self):
		self.prime = 17
		self.generator = 3
	
	def calValue(self,pK):		#pK is publicKey
		self.Value = (self.generator ** pK) % self.prime
		return self.Value
	
	def calSecret(self,p2Value,pK):
		self.S = ((p2Value % self.prime)**pK) % self.prime
		print("Secret Key of DH is: " + str(self.S))
	
	def SendSecret(self, pk):
		return self.S ^ pk
		
	def calKey(self,p2S):
		return  self.S ^ p2S
