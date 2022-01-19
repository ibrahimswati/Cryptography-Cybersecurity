import sys
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

en = "--encryption"
de = "--decryption"
pr_k = sys.argv[2]
arg = sys.argv[1]
plain_text = sys.argv[3]


if arg == en:
#Encypting data with Public and Private key
#Public and Private key
	key = RSA.generate(2048)
	private_key = key.export_key()
	file_out = open(pr_k, "wb")
	file_out.write(private_key)
	file_out.close()

	public_key = key.publickey().export_key()
	file_out = open("public.pem", "wb")
	file_out.write(public_key)
	file_out.close()

	recipient_key = RSA.import_key(open("public.pem").read())
	session_key = get_random_bytes(16)
	
	f=open(plain_text, "r")
	text=(f.read())
	data=text.encode("utf-8")
	file_out=open(plain_text,"wb")
	


# Encrypt the session key with the public RSA key
	cipher_rsa = PKCS1_OAEP.new(recipient_key)
	enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
	cipher_aes = AES.new(session_key, AES.MODE_EAX)
	ciphertext, tag = cipher_aes.encrypt_and_digest(data)
	[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
	file_out.close()


elif arg == de:

#Decrypting file
	file_in = open(plain_text, "rb")
	private_key = RSA.import_key(open(pr_k).read())
	enc_session_key, nonce, tag, ciphertext = \
	[ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

# Decrypt the session key with the private RSA key
	cipher_rsa = PKCS1_OAEP.new(private_key)
	session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
	cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
	data = cipher_aes.decrypt_and_verify(ciphertext, tag)
	sys.stdout = open(plain_text, "w")
	print(data.decode("utf-8"))
	sys.stdout.close()



