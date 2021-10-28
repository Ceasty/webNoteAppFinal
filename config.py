#python =m venv <folder>
#pip install -r requirement.txt

class Config:
	
	def __init__(self):
		self.DB_PLATFORM = 'postgresql'
		self.DB_SERVER = 'localhost'
		self.DB_NAME = 'noteapp'
		self.DB_USERNAME = ''
		self.DB_PASSWORD = ''
		self.secret_key = 'Sangat Rahasia Bro'
		

		#self.DB_URL=f"{self.DB_PLATFORM}://{self.DB_USERNAME:{self.DB_PASSWORD}@{self.DB_SERVER}/{self.DB_NAME}"
		self.DB_URL=f"{self.DB_PLATFORM}://{self.DB_SERVER}/{self.DB_NAME}"
		
		
		
