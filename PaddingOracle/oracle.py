import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import hmac
import hashlib
from Crypto.Cipher import AES

"""
This is code for the oracle or in the case of the attack the server fills this role.
Essentially the oracle will take the incoming message and determine if the padding is correct or not.
It does this by taking off the padding and then if the padding is correct it checks the MAC of the message.
This code is more or less a simplified example of how TLS decodes and encodes messages though very loosely.
"""

"""
create_mac function
Takes 
key - key used to create the mac
message - message to be mac
Returns
mac - the mac of the message

This code is very straight forward just take the message and key and use hmac library to mac the message
"""

def create_mac(key, message):
    # Create a new HMAC object using the key and SHA-256
    mac = hmac.new(key, message, hashlib.sha256)
    
    # Return the MAC in hexadecimal format
    return mac.hexdigest()



"""
verfiy_mac function
Takes 
key - key used to create the mac
message - message to be mac
mac - the mac to check 
Returns
True if the mac match for this message
False if the mac does not match

This code is very straight forward just take the message and key recreating the mac and checking if it matches
"""

def verify_mac(key, message, mac):
    # Create a new MAC for the given message
    computed_mac = create_mac(key, message)
    
    # Compare the computed MAC with the provided MAC
    return hmac.compare_digest(computed_mac, mac)


"""
encrypt function
Takes 
key - key used for encryption
message - message to be encypted
Returns
iv+encypted - this is the iv used for encrypted concat with the encyption output

This code is very straight forward just forward, we create random iv create the cipher opject using AES CBC then we create out padder and pad our message
then we run the message through the encyptor returning the result
"""


def encrypt(key,message):
    # Generate a random 16-byte IV
    iv = os.urandom(16)

    
    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad the plaintext to make it a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()

    
    # Encrypt the padded plaintext
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv+encrypted


"""
decrypt function
Takes 
key - key used for encryption
message - message to be encypted
message_mac - MAC code for the message
Returns
Message - this returns a string based on how decryption went, the three options are invalid padding (For padding errors), invalid MAC (For when the mac doesn't match), and successful decrpytion

Here we go through the oposite of the encrypt function but we need to catch any padding errors and return those for the oracle, and after decrpytion we need to verfiy the MAC.
"""

def decrypt(key, message,message_mac):    
    # Extract the IV
    encrypted_data = message
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    
    # Create a cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    # Unpad the plaintext
    try:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plain_text = unpadder.update(padded_plaintext) + unpadder.finalize()
    except:
        #Catch any errors and return a message saying invalid padding 
        #This is useful for the attack as this tells the attack that the padding was incorrect and the byte their testing is incorrect
        return "Invalid Padding"
    #Verifing the MAC, we do this as if the attack gets the correct byte and the padding is successful the decrpytion will work but won't give the orginial plaintext hence we need to check the MAC
    if verify_mac(key,plain_text,message_mac):

        return "Message Decoded"
    else:
        return "Invalid MAC"


'''
Main function where all the socket logic is

'''
def main():
    #Creating a rondom key and getting the message and creating the MAC and encyption of message
    key = os.urandom(32)
    message = input("Please enter message for Attack to decrypt:\n")
    message_mac = create_mac(key,message)
    encrypted_message = encrypt(key,message)


    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_address = ('localhost', 65433)
    server_socket.bind(server_address)

    # Listen for incoming connections
    while True:
        server_socket.listen()


        print('Waiting for a connection...')
        connection, client_address = server_socket.accept()
        connected = True

        try:
            print('Connection from', client_address)
            
            #Preform a simple hello and check with the client
            data = connection.recv(1024)
            print('Received:', data.decode())
            connection.sendall(data)  # Echo the received data back
            data = connection.recv(1024)
            print('Received:', data.decode())
            #Send over the encypted message for the attack to decrpyt
            connection.sendall(encrypted_message)
            print(encrypted_message.hex())
            #We're gonna keep recv messages as the attack is trying different bytes to decrpyt the message
            while connected == True:
                data = connection.recv(1024)
                #Shut off code to close the connection
                if data == "1".encode():
                    connected = False
                else:
                    #Send back the results of the decrypt to the attacker
                    result = decrypt(key,data,message_mac)
                    connection.sendall(result.encode())
        finally:
            connection.close()


    pass




if __name__ == "__main__":
    main()