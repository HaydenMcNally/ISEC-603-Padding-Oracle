import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

'''
This file is the attacker file is conntacts the oracle and gets the encrypted message, it then changes bytes in the message
to preform the Padding Oracle attack. Getting responses back from the oracle about how decryption went. 
'''

'''
calculate_increased_padding_byte
Takes
list - a list of bytes
rounds - the current round(the byte postion we're on 1-16)
Returns
newlist - a new list of bytes changes so that for the next round the padding is increase by 1

This function takes the list of previous dicsover answer bytes(bytes that gave correct padding) and calculate the new byte
so that in the next byte decryption the padding of the earlier bytes are the correct number.
Ex we find that for the last byte in the encypted message 0x21 is correct which means that we're decypting the last byte
to be 0x01 for the next bytes decyption for padding to be correct we need all the previous bytes to match the correct padding
so we need to figure out what byte 0x21 needs to change to so for the next decyption the padding equals 0x02 


'''
def calculate_increased_padding_byte(list,rounds):
    #Copy the list
    newlist = list
    for index,byte in enumerate(list):
        #Based on the current round when we xor the byte with the padding we know we got we get the 'cipher byte' the byte that the current byte decrypts to that gets xor with the previous block
        cipherbyte = rounds ^ byte
        #Now with the cipherbyte we can calculate the what the byte needs to be so that when XORed equals the correct padding
        newlist[index] = (rounds+1) ^ cipherbyte
        #print(f'{(rounds+1) ^ cipherbyte:02x}')
    return newlist

'''
padding_attack
Takes
encypted_message - encypted message we want to decrypt
client_socket - socket used to send data to the oracle
Returns
None

This is the meat of the attack were we preform each round to decrpyt each byte. This function goes byte by byte and block by block
It changes the byte one by one until it gets the correct error code response, it then saves that byte and calculates the decrypted byte

The Padding oracle attack works by using three bytes of information from how CBC mode works, CBC mode works by taking a byte encrypting it
with AES and getting an encrypted byte out, it then takes the corresponding byte from the previous block and xor them together to get the 
final encypted byte. The padding oracle attack using the error messages of correct padding or incorrect MAC to determine what the pervious 
blocks byte needs to be so that when xored with the encypted byte it equals proper padding which gives us the answer.
Ex. for the last byte if we get a MAC error we know the padding is correct and hence 
the output must be 0x01, we know what the pervious block byte was changed to and since in XOR , a xor b = c then b xor c = a we can calculate the encypted byte
by xoring the byte we changed the pervious block byte to with 0x01. THis gives us the encypted byte
with this we can get the unencypted message byte by xor the encypted byte with the original pervios block byte.

With that in mind this code goes through each block and byte trying each hexdigit in a spot until we get a MAC error, with that we calculate
the unencypted byte.
'''
def padding_attack(encrypt_message,client_socket):
    #Changing the encypted message into a list of the bytes this is for ease of change the bytes and know correct indexes
    attack_message_list = [f'{byte:02x}' for byte in encrypt_message]
    #Making a orginal copy of the list so that when we move onto the next block we can restore the bytes we change for decryption
    attack_message_list_og = list(attack_message_list)


    invalidPadding = True  #Varaible for loop check to see if we have valid padding or not
    decryptedMessageBytes = [] #List for the decrypted bytes so we can print the decrypted message
    previousCorrectBytes = [] #List used for keeping track of previous bytes that got valid padding used to setup message for next round
    hexdigit = 0x00 #Start hexdigit 
    startposition = len(encrypt_message) - 17 #Get the last byte in second last block
    message_length = len(encrypt_message) #Get the message length to calculate manipulate the attack message

    rounds = 1 #Round is the value of what byte in the block we're working on
    firstblock = True #The first block is handle different since is actually has padding on it so we need to handle it differently this is a check for that
    noskip = True #This is a check for when we get to the byte in the first block that matches the orginial padding as we can skip that byte we already can decrypt it
    hexdigitstring = f'{hexdigit:02x}' # Changing the hexdigit to a string so it matches type
    while startposition > -1: #We'll loop until we decrypt all of the bytes hence when the position is -1
        while invalidPadding and noskip: #if padding is invalid and we not on the skip byte we'll try to find the correct byte


            attack_message_list[startposition] = hexdigitstring #changing the current byte to our current guess

            attack_message = "".join(attack_message_list) # Reform the byte string
            
            #This if statement is an edge case as out of the 255 bytes we can put two will give correct response first the byte that gives the new valid padding that we're looking for.
            #and the orginal byte hence we need to skip the original byte and we know the original byte is going to be wrong (except for our skip edge case see noskip comment)
            if bytes.fromhex(attack_message).hex() == encrypt_message.hex():
                hexdigit += 0x01
                hexdigitstring = f'{hexdigit:02x}'
                continue
    
            client_socket.sendall(bytes.fromhex(attack_message)) #Sending back the bytes of our new encypted message
            data = client_socket.recv(1024)

            #If we got a Invalid MAC message this means the padding was correct and we found the byte we're looking for so we save it and get out of the loop
            if data.decode() == "Invalid MAC":
                invalidPadding = False #Changing to false so we stop looping
                continue #Getting out of loop
            #If we didn't get the Invalid MAC code we got a invalid padding code so we incerment the hexdigit and repeat
            hexdigit += 0x01
            hexdigitstring = f'{hexdigit:02x}'
        #If noskip was false that means were at the last original padding byte and we don't need to check it so we save it's value as correct and continue
        if not noskip:
            hexdigit = encrypt_message[startposition] #Getting the current byte in the current position no changes needed
            noskip = True #Resetting the noskip check 

        decryptedMessageBytes.append(hexdigit^encrypt_message[startposition]^rounds) #Here we take the last hexdigit the correct on xor is with the round to give the byte AES decrypts the encrypted byte to and
        #then we xor that with the original byte from the position we're on this gives us the decryption byte
        startposition -= 1 # Reduce the start position for next round
        previousCorrectBytes.append(hexdigit) # Append the correct byte to the previousCorrectBytes list so that we can use it to make the previous bytes padding corretly
        previousCorrectBytes = calculate_increased_padding_byte(previousCorrectBytes,rounds) #Calculate what they need to be for the next round

        #This for loop goes through each previous byte and changes it in the attackmessage to for the next round the padding amount will have increased
        x = 0
        for byte in previousCorrectBytes:
            attack_message_list[message_length - 17 -x] = f'{byte:02x}'
            x+=1
        
        invalidPadding = True #Reset the loop check

        rounds += 1 #Increase the round counter for the next bytes

        #This if checks to see if we're on the byte that is the first byte is the original padding as we can skip that byte
        if rounds == decryptedMessageBytes[0] and firstblock:
            noskip = False
        
        attack_message = "".join(attack_message_list) #Rejoining the newlly formed attack message 
        
        #Once the rounds hit 17 we've completed a whole block so we delete the previous block and start again with the next block
        #Here we're reduceing the message length and resetting all the counters
        if rounds == 17:
            firstblock = False #no longer on the first block so this check should always fail
            message_length -= 16 #Taking off last block from the length
            attack_message_list = attack_message_list_og[:-16] #Making the attack list from the original attack message minus last block
            attack_message_list_og = attack_message_list_og[:-16] #Reducing the original block size for the next block 
            attack_message = "".join(attack_message_list)
            rounds = 1 # Reset the rounds
            previousCorrectBytes = [] # Only need previous correct bytes for current block
        hexdigit = 0x00

    #We add the decrpyted bytes backwards into the list so we need to reverse them and then we can print out the decrypted message    
    answerstringlist = list(reversed(decryptedMessageBytes))
    print(answerstringlist)
    for chars in answerstringlist:
        if chars < 126:
            print(chr(chars), end="")
        else:
            print("1", end="")


'''
Main function that creates the socket that talks to the oracle and calls the padding attack function
'''
def main():
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    server_address = ('localhost', 65433)
    client_socket.connect(server_address)
    connected = True

    try:
        message = 'Hello, Server!'
        client_socket.sendall(message.encode())
        
        # Receive the response
        data = client_socket.recv(1024)
        print('Received from server:', data.decode())
        client_socket.sendall('0'.encode())
        encrypt_message = client_socket.recv(1024)
        while connected == True:
            padding_attack(encrypt_message,client_socket)
            connected = False
            client_socket.sendall(b'1')
    finally:
        client_socket.close()
    pass




if __name__ == "__main__":
    main()
