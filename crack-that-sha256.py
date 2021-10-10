from pwn import *
import sys
import string

def checkInput(sha256_hash):
	if len(sha256_hash) != 64: #length of hash
		print("ERROR: You entered a HASH with the wrong length, double check and try again.")
		exit()
	elif all(c in string.hexdigits for c in sha256_hash) == False:
		print("ERROR: You entered a HASH with an invalid character, double check and try again.")
		exit()

#Error checking for arguments
if len(sys.argv) != 3:
	print("ERROR: INVALID ARGUMENTS")
	print("psssst....it goes like this:")
	print("python3 {} <sha256 hash> <wordlist>".format(sys.argv[0]))
	#print(">> {} <sha256sum>".format(sys.argv[0]))
	exit()

#Assigning variables from user
sha256_hash = sys.argv[1]
wordlist = sys.argv[2]

checkInput(sha256_hash)

sha256_hash = sha256_hash.lower() #making sure hash is lowercase
print("HASH::: {}".format(sha256_hash))
attempts = 0 #internal tracking...will give user option to show in future

with log.progress("Attempting to CRACK: {}!\n".format(sha256_hash)) as p:
	with open(wordlist, "r", encoding='latin-1') as password_list:
		for password in password_list:
			password = password.strip("\n").encode('latin-1')
			hash_of_password = sha256sumhex(password) #creating a sha256sum hex of the password from the password list
			p.status(" CRACKING.........{} :: {}".format(password.decode('latin-1'), hash_of_password))
			if hash_of_password == sha256_hash:
				p.success("PASSWORD FOUND!! ::: {} :::".format(password.decode('latin-1')))
				exit()
			attempts += 1 #internal
		p.failure("NO PASSWORD FOUND")