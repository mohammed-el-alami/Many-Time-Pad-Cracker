import os
#function to compute XOR for two hexadecimals of different lengths 
def hexxor(a, b):
    if len(a) > len(b):
        c = hex(int(a[:len(b)],16)^int(b,16))[2:]
    else:
        c = hex(int(a,16)^int(b[:len(a)],16))[2:]
    if len(c)%2:
        c = "".join(['0',c])
    return c

#To generate a key with 50 bytes in Hex format
key = os.urandom(50).hex()

# Open the file in read mode
with open("simple and clair sentences not encrypted consisting only of letters and spaces.txt", "r", encoding="utf-8") as file:
    # Read all lines from the file and store them in a list
    lines = file.readlines()
# Strip whitespace and newline characters from each line
lines = [line.strip() for line in lines]


# Open a file in write mode
with open("sentences encrypted.txt", "w", encoding="utf-8") as file:   
    # Write encrypted each line by key 
    for line in lines:
        file.write(hexxor(key,line.encode('utf-8').hex()) + "\n")
