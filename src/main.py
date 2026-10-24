import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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
        with open(file_path,"r") as input_file:
                keywords=input_file.read().split()

        #generating encrypted file from plain file
        with open(file_path,"rb") as input_file:
            plaintext=input_file.read()

        #generating a random initialization vector iv and convrting to hex
        iv=os.urandom(16)

        #encrypting plaintext with AES secret key sk1 and initialization vector iv
        cipher=AES.new(sk2,AES.MODE_CBC,iv)
        ciphertext=iv+cipher.encrypt(pad(plaintext,AES.block_size))
        ciphertext=ciphertext.hex()
        #saving encrypted file
        encrypted_filepath = os.path.join(encrypted_folder_path,"enc_"+file)
        with open(encrypted_filepath,"w") as output_file:
            output_file.write(ciphertext)

        #using AES-ECB-256 to simulatio PRF to encrypt each keyword
        for word in keywords:
            cipher=AES.new(sk1,AES.MODE_ECB)
            encrypted_word=cipher.encrypt(pad(word.encode("utf-8"),AES.block_size)).hex()

            if encrypted_word not in encrypted_index:
                encrypted_index[encrypted_word]=[]
            if file not in encrypted_index[encrypted_word]:
                encrypted_index[encrypted_word].append(file)

    with open("data/index.txt","w") as file:
        for keyword, files in encrypted_index.items():
            file.write(keyword+" "+" ".join(files)+"\n")

    print("encrypted index:")   
    for keyword, files in encrypted_index.items():
        print("Encrypted keyword:", keyword)
        print("Files:", files)  
    return

#-------- TASK 3. TOKEN GENERATION FUNCTION ----------
def token_generation(keyword):
    print("\n-------TASK 3. KEY GENERATION FUNCTION--------------")
    #reading a secret key k1 from skprf.txt file
    with open("data/skprf.txt","r") as file:
            sk1=file.read().strip()
    sk1=bytes.fromhex(sk1)
    #generating token tk
    cipher=AES.new(sk1,AES.MODE_ECB)
    tk=cipher.encrypt(pad(keyword.encode("utf-8"),AES.block_size))
    tk=tk.hex()

    print("keyword: ",keyword)
    print("generated token: ",tk)

    with open("data/token.txt","w") as file:
        file.write(tk)
    return

#-------- TASK 4. SEARCH FUNCTION ----------
def search(token_filepath="data/token.txt", encrypted_folder_path="data/encrypted_files"):
    print("\n-------TASK 4. SEARCH FUNCTION--------------")
    #reading a token tk file
    with open(token_filepath,"r") as file:
        tk=file.read().strip()

    with open("data/skaes.txt","r") as file:
        sk2=file.read().strip()
    sk2=bytes.fromhex(sk2)

    matching_files=[]
    with open("data/index.txt","r") as file:
        for line in file:
            values=line.split()
            if values and values[0]==tk:
                matching_files=values[1:]
                break

    with open("data/result.txt","w") as file:
        if len(matching_files)>0:
            print("files found with the keyword:"," ".join(matching_files))
            file.write(" ".join(matching_files)+"\n")

            for filename in matching_files:
                filepath=os.path.join(encrypted_folder_path,"enc_"+filename)
                with open(filepath,"r") as encrypted_file:
                    ciphertext=bytes.fromhex(encrypted_file.read().strip())

                iv=ciphertext[:AES.block_size]
                ciphertext=ciphertext[AES.block_size:]

                cipher=AES.new(sk2,AES.MODE_CBC,iv)
                plaintext=unpad(cipher.decrypt(ciphertext),AES.block_size).decode("utf-8")
                print(filename,plaintext)
                file.write(filename+" "+plaintext+"\n")

    return

key_generation()
encryption()
token_generation("packers")
search()