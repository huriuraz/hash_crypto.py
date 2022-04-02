import base64
import pyAesCrypt
import uuid
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class Sifreleme:
    def __init__(self, input, key):
        self.input = input
        self.key = key

    def __eq__(self, other):
        return self.input == other.input and self.key == other.key

    def __hash__(self):
        return hash((self.input, self.key))


bufferSize = 64 * 1024
password = "C:/Users/Samsung/Desktop/key.txt"
# encrypt
enc = base64.b64encode(bytes("input.txt", encoding="UTF-8"))
sonenc = base64.b64encode(bytes("encrypt.txt", encoding="UTF-8"))

plaintext = pyAesCrypt.encryptFile("C:/Users/Samsung/Desktop/input.txt", "C:/Users/Samsung/Desktop/encrypt.txt",
                                      password,
                                      bufferSize)
enc3 = open("C:/Users/Samsung/Desktop/hash.txt", "wb")

print("""
1.ŞİFRELE
2.SİFREYİCÖZ
3.Açık metine hash işlemi uygula
4.Şifreli metine hash işlemi uygula
5.Anahtar a  hash işlemi uygula
6.Çıkış
""")
while True:
    ans = input("bir seçim yapınız ")
    try:
        text = open("C:/Users/Samsung/Desktop/input.txt", "r")

    except FileNotFoundError:
        print("\nDosya bulunamadı tekrar deneyiniz...")

    if ans == "1":

            plaintext = pyAesCrypt.encryptFile("C:/Users/Samsung/Desktop/input.txt", "C:/Users/Samsung/Desktop/encrypt.txt",
                                          password,
                                          bufferSize)

    elif ans == "2":
        # decrypt
        ciphertext = pyAesCrypt.decryptFile("C:/Users/Samsung/Desktop/encrypt.txt", "C:/Users/Samsung/Desktop/dataout.txt", password,
                                      bufferSize)
        cozulmushash=Sifreleme(ciphertext,password)
        print("Çözülen metinin hash sonucu : %d" %hash(ciphertext))

    elif ans == "3":
        plain = Sifreleme(enc, password)

        print("Açık metin hash sonucu: %d" % hash(plain))



    elif ans== "4":
        cipher = Sifreleme(plaintext, password)

        print("şifreli metin hash sonucu: %d" % hash(cipher))


    elif ans== "5":
        sayac = 0
        while sayac < 100:

            x = hash(password)
            print(x)
            keyhash = open("C:/Users/Samsung/Desktop//key_hash.txt", "w")
            keyhash.write(str(x))

            sayac = sayac + 1

        sonenc=pyAesCrypt.encryptFile("C:/Users/Samsung/Desktop/input.txt", "C:/Users/Samsung/Desktop/encrypt.txt",str(x),bufferSize)


    elif ans=="6":
        message = "ascbdfgh"
        digest = SHA256.new()
        digest.update(message)

        private_key = False
        with open("C:/Users/Samsung/Desktop/input.txt", "r") as dosya:
            private_key = RSA.importKey(dosya.read())

        signer = PKCS1_v1_5.new(private_key)
        sig = signer.sign(digest)

        verifier = PKCS1_v1_5.new(private_key.publickey())
        verified = verifier.verify(digest, sig)
        assert verified, 'imza dogrulanamadı'
        print('baaşarılı')

    elif ans== "7":
        exit()
