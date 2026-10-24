import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

#-------TASK 1. KEY GENERATION FUNCTION--------------
def key_generation(lam=256):
    print("\n-------TASK 1. KEY GENERATION FUNCTION--------------")
    #generating secret key of 256 bits for PRF and AES
    sk1=os.urandom(lam//8)
    sk2=os.urandom(lam//8)

    #converting to hex
    sk1=sk1.hex()
    sk2=sk2.hex()

    #printing secret key to terminal
    print("PRF Secret key (sk1):",sk1)
    print("AES Secret key (sk2):",sk2)

    #writing key to file
    with open("data/skprf.txt","w") as file:
        file.write(sk1)

    with open("data/skaes.txt","w") as file:
        file.write(sk2)
    return

#-------- TASK 2. ENCRYPTION FUNCTION ----------
def encryption(files_folder_path="data/files",encrypted_folder_path="data/encrypted_files"):
    print("\n-------TASK 2. ENCRYPTION FUNCTION--------------")
    #reading secret key sk1 and sk2 from file
    with open("data/skprf.txt","r") as file:
        sk1=file.read().strip()
    with open("data/skaes.txt","r") as file:
        sk2=file.read().strip()
    sk1=bytes.fromhex(sk1)
    sk2=bytes.fromhex(sk2)

    encrypted_index={}

    for file in os.listdir(files_folder_path):
        file_path=os.path.join(files_folder_path,file)
        with open(file_path,"r") as file:
                keywords=file.read().split()

        #generating encrypted file from plain file
        with open(file_path,"rb") as file:
            plaintext=file.read()

        #generating a random initialization vector iv and convrting to hex
        iv=os.urandom(16)
        iv=iv.hex()

        #padding the plaintext because it only encrypts in sections of 16 bytes
        #so the message needs the to be padded to that
        padding_length=AES.block_size-(len(plaintext)%AES.block_size)
        plaintext=plaintext+bytes([padding_length])*padding_length

        #encrypting plaintext with AES secret key sk1 and initialization vector iv
        cipher=AES.new(sk1,AES.MODE_CBC,iv)
        ciphertext=cipher.encrypt(plaintext)
        ciphertext=ciphertext.hex()
        #saving encrypted file
        encrypted_filepath = os.path.join(encrypted_folder_path,file + "_enc")
        with open(encrypted_filepath,"wb") as file:
            file.write(ciphertext)

        #using AES-ECB-256 to simulatio PRF to encrypt each keyword
        for word in keywords:
            cipher=AES.new(sk1,AES.MODE_ECB)
            encrypted_word=cipher.encrypt(pad(word.encode("utf-8"),AES.block_size)).hex()

            if encrypted_word not in encrypted_index:
                encrypted_index[encrypted_word]
            if file not in encrypted_index[encrypted_word]:
                encrypted_index[encrypted_word].append(file)

        with open("data/index.txt","w") as file:
            for keyword, files in encrypted_index.items():
                file.write(keyword+" "+" ".join(files)+"\n")
        
        
    return







key_generation()