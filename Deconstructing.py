from Crypto.PublicKey import DSA 
from Crypto.Signature import DSS 
from Crypto.Hash import SHA256 
from base64 import b64encode
import binascii
import json
#Pay-to-Pubkey-Hash
with open("Transaction_Format.JSON") as f:
  transaction_json = json.load(f) #Load the JSON

stack = [] #Stack
print("\n------\nStack Length "+str(len(stack))+"\n------\n")

#<sig> <pubKey>:
stack.append(transaction_json["Sig"]) # JSON Sig is in Hex format
stack[0] = stack[0][2:] # Remove 0x Hex format
stack[0] = binascii.unhexlify(stack[0]) #Unhexifiy

stack.append(transaction_json["pubkey"]) #JSON pubKey is in HEX format
stack[1] = int(stack[1],16) # Convert Hex to Integer
print("\n------\nStack Length "+str(len(stack))+"\n[0]Sig: "+ str(stack[0]) + "\n[1]pubkey: "+ str(stack[1])+"\n------\n")

#OP_DUP:
stack.append(stack[len(stack)-1]) # Top Stack item is duplicated
print("\n------\nStack Length "+str(len(stack))+"\n[0]Sig: "+ str(stack[0]) + "\n[1]pubkey: "+ str(stack[1])+"\n[2]pubkey: "+ str(stack[2])+"\n------\n")

#OP_HASH160 Computes the 160 least signigicant bits of SHA256 hash value of the last value in the stack 
stack[2] = bytes(str(stack[2]), 'utf-8') # Converts int public key dup to str and then Str to Byte
hash_pub_key = SHA256.new(stack[2])  # Hashes byte public key
hash_pub_key = hash_pub_key.hexdigest() # Turns Bytes to hexadecimal 
stack[2] =  binascii.unhexlify(hash_pub_key[-40:])   # Only adds the 160 least significant bits of hash value
print("\n------\nStack Length "+str(len(stack))+"\n[0]Sig: "+ str(stack[0]) + "\n[1]pubkey: "+ str(stack[1])+"\n[2]pubHashA: "+ str(stack[2])+"\n------\n")

# <pubKeyHash>
stack.append(transaction_json["pubKeyHash"]) #JSON pubKeyHash is in HEX format
stack[3] = stack[3][2:] # Remove 0x Hex format
stack[3] = binascii.unhexlify(stack[3]) # remove leading 0x
print("\n------\nStack Length "+str(len(stack))+"\n[0]Sig: "+ str(stack[0]) + "\n[1]pubkey: "+ str(stack[1])+"\n[2]pubHashA: "+ str(stack[2])+"\n[3]pubKeyHash: "+ str(stack[3])+"\n------\n")

# OP_EQUALVERIFY Equality is checked between the top two stack items.
print("\nEquality is checked between the top two stack items")
if(stack[len(stack)-2] == stack[len(stack)-1]):
  print("[2]pubHashA: "+ str(stack[2])+" == [3]pubKeyHash: "+ str(stack[3]))
  stack.remove(stack[3])
  stack.remove(stack[2])

  print("------\nStack Length "+str(len(stack))+"\n[0]Sig: "+ str(stack[0]) + "\n[1]pubkey: "+ str(stack[1]))
else:
  print("[2]pubHashA: "+ str(stack[2])+" != [3]pubKeyHash: "+ str(stack[3]))

# OP_CHECKSIG Signature is checked for top two stack items.
#Converting all the Hex (0x...) into ints
tup = [int(stack[1]), int(transaction_json["DSAParam"][0],16), int(transaction_json["DSAParam"][1],16), int(transaction_json["DSAParam"][2],16)]


pub_key = DSA.construct(tup)
hash_obj = SHA256.new(b"Cybersecurity is cool!")
verifier = DSS.new(pub_key, 'fips-186-3')
try:
  verifier.verify(hash_obj, stack[0]) 
  print("The message is authentic.")
except ValueError:
  print("The message is not authentic.")
