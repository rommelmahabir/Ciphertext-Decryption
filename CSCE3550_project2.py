'''
	Name: Rommel Mahabir (rsm0169)
	Course: CSCE3550.001
	Project 2 - Cryptography
	Date: 4/18/2022

	DESCRIPTION:
	           This program decrypts as much ciphertexts as possible created by
               using a many-time pad by using a technique of XOR'ing to exploit
               the vulnerability.
'''

import sys

# This function matches the the hex value to a letter by XORing with the hex value of SPACE until a match is found
# Because this function is only ever called if a SPACE is found in the colunm, there is no need to worry about it not
# hitting a return
def decipher(space, letter):
    ref = list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") # List of all possible words for this project

    for char in ref:
        if (ord(char)^32 == int(space,16)^int(letter,16)):
            return char
        elif (int(space,16)^int(letter,16) == 0):
            return " "

    return "_" # If this is output, then something went wrong

# Scans through the cipher message
def scanMessages(ctxts):
    # Raw message stored here in list form for easy of mutability
    messages = []
    for i in range(0,len(ctxts)): # Fill it in with "_" by default
        line = ["_"] * 60
        messages.append(line[:])

    # Bulk of the deciphering goes here
    for i in range(0,120,2):
        spaceLoc = -1 # Indicates that no SPACE was found

        # Two vars to be used in the case that the SPACE is in the first message
        zeroCnt = 0
        above65 = 0

        # XOR checking for values greater than 65, usually indicative of SPACEs
        for j in range(1, len(ctxts)):
            xor_val = int(ctxts[0][i:i+2],16) ^ int(ctxts[j][i:i+2],16)
            if xor_val >= 65: # Handles special case mentioned above
                spaceLoc = j
                above65+=1
            elif xor_val == 0: # In the case of multiple SPACE in column while special case is active
                zeroCnt+=1

        # If spaceLocation remains at -1, no SPACE was found, loop back
        if spaceLoc == -1:
            continue

        # When the number of rows minus the number XOR 0s, matches the number of of XOR above 65,
        # then the SPACE is in the first column
        if (above65 == (len(ctxts)-(1+zeroCnt))):
            spaceLoc = 0

        # Location of SPACE
        space = ctxts[spaceLoc][i:i+2]

        # Sends column of to decipher function, returns to raw message list
        for j in range(0, len(ctxts)):
            messages[j][int(i/2)] = decipher(space, ctxts[j][i:i+2])

    # Turns raw message into list of strings
    c_messages = []
    for msg in messages:
        c_messages.append("".join(msg))

    # Cleaned up
    c_messages = '\n'.join(c_messages)

    # Returns Cleaned Messages
    return c_messages[:]

# Main function B)
def main():
    ''' Left over code input file as command line argument
    if len(sys.argv) != 2:
        print("Run using genCipherMsgs1.py <cipherFile>")
        sys.exit()
    '''

    # Takes user input on filename
    filename = input("Enter the name of the ciphertexts file: ")

    # Catches nonexistant filename, will terminate program
    try:
        with open(filename, "r") as file: # This will automatically close the open file once it's done
            ctxts = file.read().splitlines()
    except FileNotFoundError:
        print("File does not exist... Exiting Program")
        sys.exit()

    # Prints Decoded Message
    print("Plaintext Messages:")

    decrypted_msgs = scanMessages(ctxts)
    print(decrypted_msgs)

# Main
if __name__ == "__main__":
    main()
