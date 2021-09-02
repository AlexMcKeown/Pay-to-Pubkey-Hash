from Crypto.PublicKey import DSA 
from Crypto.Signature import DSS 
from Crypto.Hash import SHA256 
from base64 import b64encode
import binascii
import json

def formatHex(temp_key):
    return "\""+hex(temp_key)+"\""

file_in = open("Transaction_Format.JSON","r+")
content = file_in.read()

#DSAParam & pubkey
key = DSA.generate(2048) # Generates a 2048 Bit public key 
key_chain = [key.y, key.g, key.p, key.q] # Key y is the Public Key | Key G P Q are the DSA Param
print("SigningKey: "+ str(key.x))
#Write to JSON file here <pubKey> <g> p q #Must be hexadecimal
content = content.replace('<g>', formatHex(key.g)) # Int to String formatHex
content = content.replace('<p>', formatHex(key.p))
content = content.replace('<q>', formatHex(key.q))
content = content.replace('<pubKey>', formatHex(key.y))

#Sig
message = b"Cybersecurity is cool!"
hash_obj = SHA256.new(message) 
signer = DSS.new(key, 'fips-186-3') 
signature = signer.sign(hash_obj)
#Write to JSON file here <sig> #Must be hexadecimal
signature_hexed ="\"0x" #Formating JSON
signature = binascii.hexlify(signature) #  Byte to String Hex 
signature = signature.decode('utf-8')
signature_hexed += signature
signature_hexed +="\"" #Formating JSON

content = content.replace('<sig>', str(signature_hexed) )

#pubKeyHash
pub_key = bytes(str(key.y), 'utf-8') # Converts int public key to str and then Str to Byte
hash_pub_key = SHA256.new(pub_key)  # Hashes byte public key
hash_pub_key = hash_pub_key.hexdigest() # Turns Bytes to hexadecimal 
hash_pub_key_hexed ="\"0x" #Formating JSON
hash_pub_key_hexed += hash_pub_key[-40:]
hash_pub_key_hexed +="\"" #Formating JSON
#Write to JSON file here <pubKeyHash> #Must be hexadecimal 160 bits = 20 Bytes = 40Hex
content = content.replace('<pubKeyHash>', hash_pub_key_hexed) # Only adds the 160 least significant bits of hash value

#Update Transaction_Format.JSON
file_in.seek(0) # Go back to the start of the file
file_in.write(content) # Update JSON file
file_in.close() # Close JSON file
