import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#-------TASK 1. KEY GENERATION FUNCTION--------------
def key_generation(sk1_filepath,sk2_filepath,lam=256):
    if lam != 256:
        print("error! security parameter should be 256")
        return
    sk1_folder=os.path.dirname(sk1_filepath)
    if sk1_folder and not os.path.isdir(sk1_folder):
        os.makedirs(sk1_folder)
        print("created secret key folder because it did not exist: ", sk1_folder)
    sk2_folder=os.path.dirname(sk2_filepath)
    if sk2_folder and not os.path.isdir(sk2_folder):
        os.makedirs(sk2_folder)
        print("created secret key folder because it did not exist: ", sk2_folder)

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
    with open(sk1_filepath,"w") as file:
        file.write(sk1)

    with open(sk2_filepath,"w") as file:
        file.write(sk2)
    return

#-------- TASK 2. ENCRYPTION FUNCTION ----------
def encryption(data_files_folder_path,ciphertext_folder_path,sk1_filepath,sk2_filepath,index_filepath):
    if not os.path.isdir(data_files_folder_path):
        print("error: the specified path for the data files folder does not exist in the current directory")
        return
    if not os.path.isdir(ciphertext_folder_path):
        print("created ciphertext folder because it did not exist: ",ciphertext_folder_path)
        os.makedirs(ciphertext_folder_path)
    if not os.path.isfile(sk1_filepath):
        print("error! the specified file sk1 for PRF does not exist in the current directory: ",sk1_filepath)
        return
    if not os.path.isfile(sk2_filepath):
        print("error! the specified file sk2 for AES does not exist in the current directory: ",sk2_filepath)
        return
    index_folder=os.path.dirname(index_filepath)
    if index_folder and not os.path.isdir(index_folder):
            os.makedirs(index_folder)
            print("created index folder because it did not exist: ", index_folder)
    print("\n-------TASK 2. ENCRYPTION FUNCTION--------------")
    #reading secret key sk1 and sk2 from file
    with open(sk1_filepath,"r") as file:
        sk1=file.read().strip()
    with open(sk2_filepath,"r") as file:
        sk2=file.read().strip()
    sk1=bytes.fromhex(sk1)
    sk2=bytes.fromhex(sk2)

    encrypted_index={}

    for file in os.listdir(data_files_folder_path):
        file_path=os.path.join(data_files_folder_path,file)
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
        if file.startswith("f") and file[1:].split(".")[0].isdigit():
            ciphertext_file="c"+file[1:]
        else:
            ciphertext_file="c_"+file
        encrypted_filepath = os.path.join(ciphertext_folder_path,ciphertext_file)
        with open(encrypted_filepath,"w") as output_file:
            output_file.write(ciphertext)

        #using AES-ECB-256 to simulatio PRF to encrypt each keyword
        for word in keywords:
            cipher=AES.new(sk1,AES.MODE_ECB)
            encrypted_word=cipher.encrypt(pad(word.encode("utf-8"),AES.block_size)).hex()

            if encrypted_word not in encrypted_index:
                encrypted_index[encrypted_word]=[]
            if ciphertext_file not in encrypted_index[encrypted_word]:
                encrypted_index[encrypted_word].append(ciphertext_file)

    with open(index_filepath,"w") as file:
        for keyword, files in encrypted_index.items():
            file.write(keyword+" "+" ".join(files)+"\n")

    print("encrypted index:")   
    for keyword, files in encrypted_index.items():
        print("Encrypted keyword:", keyword)
        print("Files:", files)  
    return

#-------- TASK 3. TOKEN GENERATION FUNCTION ----------
def token_generation(keyword,sk1_filepath,token_filepath):
    print("\n-------TASK 3. TOKEN GENERATION FUNCTION--------------")
    if not os.path.isfile(sk1_filepath):
        print("error! the specified file sk1 for PRF does not exist in the current directory: ",sk1_filepath)
        return
    #reading a secret key k1 from skprf.txt file
    with open(sk1_filepath,"r") as file:
            sk1=file.read().strip()
    sk1=bytes.fromhex(sk1)
    #generating token tk
    cipher=AES.new(sk1,AES.MODE_ECB)
    tk=cipher.encrypt(pad(keyword.encode("utf-8"),AES.block_size))
    tk=tk.hex()

    print("keyword: ",keyword)
    print("generated token: ",tk)

    token_folder=os.path.dirname(token_filepath)
    if token_folder and not os.path.isdir(token_folder):
        os.makedirs(token_folder)
        print("created token folder because it did not exist: ", token_folder)

    with open(token_filepath,"w") as file:
        file.write(tk)
    return

#-------- TASK 4. SEARCH FUNCTION ----------
def search(token_filepath, encrypted_folder_path,sk2_filepath, index_filepath,result_path):
    print("\n-------TASK 4. SEARCH FUNCTION--------------")
    if not os.path.isfile(token_filepath):
        print("error! the specified file for the token does not exist in the current directory: ",token_filepath)
        return
    if not os.path.isdir(encrypted_folder_path):
        print("error! the specified path for the ciphertext folder does not exist in the current directory: ",encrypted_folder_path)
        return
    if not os.path.isfile(sk2_filepath):
        print("error! the specified file sk2 for AES does not exist in the current directory: ",sk2_filepath)
        return
    if not os.path.isfile(index_filepath):
        print("error! the specified index file does not exist in the current directory: ",index_filepath)
        return
    
    #reading a token tk file
    with open(token_filepath,"r") as file:
        tk=file.read().strip()

    with open(sk2_filepath,"r") as file:
        sk2=file.read().strip()
    sk2=bytes.fromhex(sk2)

    matching_files=[]
    with open(index_filepath,"r") as file:
        for line in file:
            values=line.split()
            if values and values[0]==tk:
                matching_files=values[1:]
                break

    result_folder=os.path.dirname(result_path)
    if result_folder and not os.path.isdir(result_folder):
        os.makedirs(result_folder)
        print("created result folder because it did not exist: ", result_folder)
    with open(result_path,"w") as file:
        if len(matching_files)>0:
            print("files found with the keyword:"," ".join(matching_files))
            file.write(" ".join(matching_files)+"\n")

            for filename in matching_files:
                filepath=os.path.join(encrypted_folder_path,filename)
                with open(filepath,"r") as encrypted_file:
                    ciphertext=bytes.fromhex(encrypted_file.read().strip())

                iv=ciphertext[:AES.block_size]
                ciphertext=ciphertext[AES.block_size:]

                cipher=AES.new(sk2,AES.MODE_CBC,iv)
                plaintext=unpad(cipher.decrypt(ciphertext),AES.block_size).decode("utf-8")
                print(filename,plaintext)
                file.write(filename+" "+plaintext+"\n")

    return

if __name__ == "__main__":
    key_generation("data/skprf.txt","data/skaes.txt",256)

    encryption("data/data_files","data/ciphertextfiles","data/skprf.txt","data/skaes.txt","data/index.txt")

    token_generation("packers", "data/skprf.txt", "data/token.txt")

    search("data/token.txt", "data/ciphertextfiles", "data/skaes.txt", "data/index.txt", "data/result.txt")