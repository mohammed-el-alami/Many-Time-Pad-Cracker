#### 1-The Mechanics of One Time Pad (OTP) and the Risk of Many Time Pad (MTP) : 
One Time Pad (OTP) encrypts messages by converting characters and keys into binary or hexadecimal, then applying XOR between corresponding bits to produce ciphertext. Decryption reverses this by XORing the ciphertext with the same key. If the key is reused (Many Time Pad - MTP), it creates vulnerabilities, enabling attackers to analyze ciphertexts and infer information.

Exemple :

Message: HELLO → Hex: 48 45 4C 4C 4F

Key: XMCKL → Hex: 58 4D 43 4B 4C

Ciphertext: XOR → 10 08 0F 07 03





#### 2-Exploiting Key Reuse in One Time Pad (MTP) : 
If the same key is reused for encryption, such as c1 = k xor m1 and c2 = k xor m2, attackers can exploit this. By applying XOR between the two ciphertexts c1 xor c2 , the key k is eliminated, leaving m1 xor m2 . Since the ciphertexts c1 and c2 are known, it becomes easy to calculate m1 xor m2 . If we know the value of m1 xor m2 , we can deduce several things :


a-I would like to highlight that most characters commonly used in texts, such as uppercase and lowercase letters, have ASCII values ranging from 40 to 7F. Only the space character (espace) has an ASCII value of 20.
[![image.png](https://i.postimg.cc/jq1v4MpS/ascii-table.png)](https://postimg.cc/3WggKFrs)
b-On the other hand, if we perform XOR between a hexadecimal number between 40 and 7F and the value 20, we will get another number also between 40 and 7F. However, if we perform XOR between a number between 40 and 7F and another number between 40 and 7F, the result will be between 00 and 3F, meaning it will never be between 40 and 7F.

Because, when calculating the XOR between two characters, such as 33 xor 67 , we compute 3 xor 6  to determine the left digit and 3 xor 7 to determine the right digit.

For 20 xor numbers between 40 and 7F , we calculate 2 xor 4,5,6,7 , which always gives the results: 4,5,6,7(numbers bmbetween 40 and 7F).

When performing XOR between characters ranging from 40 to 7F with each other, the 4,5,6,7 digits XORed together always yield 0,1,2,3(numbers bmbetween 40 and 7F). (The result is 0 if the two characters have the same left digit).

2 xor 4 = 6   and   2 xor 5 = 7   and   2 xor 6 = 4   and   2 xor 7 = 5

4 xor 5 = 1   and   4 xor 6 = 2   and   4 xor 7 = 3   and   5 xor 6 = 3   and   5 xor 7 = 2   and   6 xor 7 = 1

c-So, if we calculate c1 xor c2  and know the value of m1 xor m2 , and if the result is between 40 and 7F, it strongly suggests that one of the characters(m1 or m2) is a space and the other(m1 or m2) is a letter. If we know that the text only contains letters and spaces, then this hypothesis is 100% correct. However, if the result is between 00 and 3F, both characters are likely letters, except if the result is 00, in which case both might be spaces (espaces).


d-If the XOR result between two characters is between 40 and 7F, we know that one of them is a space (espace). To identify which one is the space, we test one of the characters against other letters. If all the XOR results with the other letters are between 40 and 7F, then that character is the space. However, if there is only one XOR result outside the range of 40 and 7F (and it is not 00), then the other character is the space.

However, if the text contains only one letter and the rest are spaces, or only one space and the rest are the same letter, it becomes impossible to determine which is the space because both scenarios produce identical results, making it impossible to distinguish between them.

e-The great thing is that when we know only part of the key, we can partially decrypt , revealing some words almost fully. Once we recognize these words, we can easily complete the rest of the key.





#### 3-Building scripts to attempt exploiting the key reuse vulnerability (MTP) : 

1-First, we will create a Python script to perform XOR testing between all characters of the ciphertexts encrypted with the same key. Which helps us identify some bytes of the key.
```python
cc = lines_encrypted.copy() #To make any changes without affecting the correct lines
#To determine the length of the lines in order to create a key matching the longest line
ccc = [0]*len(cc) 
for i in range(len(cc)) : 
    ccc[i]=len(cc[i])
nkey = [0] * max(ccc)
#To determine the part of the key to work on, the text must include at least one letter, one space, and another letter different from the first.
#This requires at least 3 sentences with lengths equal to or greater than the length we are working on.
while (sum(1 for i in ccc if i==max(ccc)) <= 2) : 
    r=ccc.index(max(ccc))
    ccc[r]=max(ccc)-1
#Since each character is 1 byte (8 bits), and the length in Hexadecimal is represented as 4 bits per digit, we divide the number of Hex digits by 2
#to determine the number of characters or bytes to process
for a in range(int(max(ccc) / 2)):
    ci = '00' #To place the character from the encrypted line that corresponds to an unencrypted character which is a space (espace)
    l = 0 #Just to check if we found the character in the key. If l=1, it means we found the key character; if l=0, it means we didn’t
    for i in range(len(cc) - 1):
        for j in range(i + 1, len(cc)): #We use 2 loops to perform XOR between all the characters of the lines with each other
            if len(cc[i]) <= a * 2 or len(cc[j]) <= a * 2: 
                continue #To avoid a list index out-of-bounds error
            if int(hexxor(cc[i][a * 2], cc[j][a * 2])) in [4, 5, 6, 7]: #If the XOR result is 4, 5, 6, or 7, it means one is a space (espace) and the other is a letter (lettre)
                for k in range(len(cc)): #To determine exactly which one is the space (espace)
                    if k == i or k == j or len(cc[k]) <= a * 2: 
                        continue #To avoid a list index out-of-bounds error and performing xor again between i and j
                    if int(hexxor(cc[i][a * 2], cc[k][a * 2])) not in [4, 5, 6, 7] and hexxor(cc[i][a * 2:a * 2+2], cc[k][a * 2:a * 2+2]) != '00' :
                        ci = cc[j][a * 2:a * 2 + 2]
                        break #If the XOR result is different from 4, 5, 6, or 7, it means the operation was between two letters (lettres) or two spaces (espaces).
                             #If the result is not 00, it means the operation was between two different letters. Therefore, the other character is a space (espace)
                    else:
                        ci = cc[i][a * 2:a * 2 + 2] #If all XOR results with the character at index i are also 4, 5, or 6, or 7, it means it is is an espace
                l = 1 #because the XOR result is 4, 5, 6, or 7, it means one is a space (espace) and the other is a letter (lettre)
                break
        if l == 1: #If l=1, it means m is a space (espace). Therefore, the key is the result of XOR between c and the m key we defined
            nkey[a * 2:a * 2 + 2] = hexxor(ci, '20') 
            break
    if l == 0: #If we don't get any result, we change c to 21 and key to 00 to get a "!" marker wherever we haven't found the key
        for i in range(len(cc)): #This loop is for the characters that are smaller than the part of the key we are working on
            if len(cc[i]) <= a * 2:
                continue #To avoid a list index out-of-bounds error
            cc[i] = list(cc[i]) #to change cc from str to list to can perform changes
            cc[i][a * 2:a * 2 + 2] = '21' #to change c to 21
            cc[i] = ''.join(cc[i]) #to change cc from list to str to can perform hexxor 
        nkey[a * 2:a * 2 + 2] = '00' #to change k to 00
for i in range(len(cc)): #This loop is for the characters that are larger than the part of the key we worked on
    if len(cc[i]) > max(ccc) :
        cc[i] = list(cc[i])
        for j in range(max(ccc),len(cc[i]),2) :
            cc[i][j:j+2] = '21'
            nkey[j:j+2] = '00'
        cc[i] = ''.join(cc[i])
nkey = ''.join(nkey)
```

2-After, we will display the characters for which we were able to find the key to decrypt, while the characters we couldn't decrypt will appear with a "!" symbol.
```python
#to display the characters for which we were able to find the key to decrypt, 
#while the characters we couldn't decrypt will appear with a "!" symbol
for i in range(len(cc)) : 
    print(bytes.fromhex(hexxor(nkey,cc[i])).decode('utf-8'))
```
[![image.png](https://i.postimg.cc/vB8Hc2Tj/1.png)](https://postimg.cc/WDKPynM6)

3-After that, we will be able to identify some words even if they contain a "!" symbol, as the other characters are visible. We will be able to guess the word and thus identify the hidden character. We will then create a function that performs XOR between the unencrypted and encrypted character to deduce the key, and from there, we can figure out the other sentences encrypted with the same key. We will continue this process until we find the entire key.
```python
#function to determine the key if we deduced one of the hidden characters in the previous step
#l takes the value of the line number where we identified the character, and the line numbers start from 1
#i is the character index
#c is the character itself
#The other variables were explained earlier
def pe(l,i,c,nkey,cc,lines_encrypted):
    nkey[2*i-2:2*i] = hexxor(lines_encrypted[l-1][2*i-2:2*i], format(ord(c), "x")) #Calculate the XOR between the assumed character from the sentences and the byte in the encrypted line to find the key
    for j in range(len(cc)) : #To replace the correct encrypted byte with the byte we previously set to 21 as a "!" marker, so that when we XOR the key with the encrypted byte, the correct decrypted character appears
        cc[j] = list(cc[j])
        cc[j][2*i-2:2*i] = lines_encrypted[j][2*i-2:2*i]
        cc[j] = ''.join(cc[j])
    nkey = ''.join(nkey)
    print(nkey)
    for i in range(len(cc)) : #To display the sentences with the characters we successfully decrypted
        print(bytes.fromhex(hexxor(nkey,cc[i])).decode('utf-8'))
```
[![image.png](https://i.postimg.cc/T1gRsz4K/2.png)](https://postimg.cc/V0sQrV1w)
...

...

...

...

...

...

[![image.png](https://i.postimg.cc/9FBRbkwx/t.png)](https://postimg.cc/Tpp3YC9m)
