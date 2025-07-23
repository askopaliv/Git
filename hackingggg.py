import hashlib

def find_pw(hashed_pw):
    for n in range(100000):
        if hashlib.md5(str(n).encode()).hexdigest() == hashed_pw:
            return n
        n = n +1
    print("Password not found in range 0-99999")