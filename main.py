import string
import math


def readfile(filename):
    stream = open(filename,'r')
    filetext = stream.read()
    stream.close()
    return filetext


def writefile(filename, text):
    stream = open(filename, 'w')
    stream.write(text)
    stream.close()
    return


# bin_to_string(binary)
# entrada: binary: string con 0s y 1s que representan caracteres en binario
# salida: final_string: el string resultante de decodificar la entrada
def bin_to_string(binary):
    final_string = ""
    for i in range(0, len(binary), 8):
        letter = binary[i:i+8]
        decimal = int(letter, 2)
        final_string = final_string + chr(decimal)
    return final_string


# caesar(plaintext, key)
# entrada: plaintext: texto a encriptar
#          key: clave a utilizar para el encriptado
# salida: ciphertext: texto encriptado
# implementación del cifrado cesar, utilizando como alfabeto los caracteres unicode
def caesar(plaintext, key):
    ciphertext = ""
    for letter in plaintext:
        shifted = (ord(letter) + key)%256
        ciphertext = ciphertext + chr(shifted)
    return ciphertext


# xor(plaintext, key)
# entrada: plaintext: texto a encriptar
#          key: clave a utilizar para el encriptado
# salida: cipherbits: texto encriptado (en binario)
# implementación del cifrado xor, utilizando como alfabeto los caracteres unicode. Ya que se requiere una clave en bits,
# se transforma la clave original a codigo binario. Si la clave es mas corta que el textoplano, entonces se agrega a la
# clave original la misma clave original pero alterada i veces (se le suma 1 en cada iteración)
def xor(plaintext, key):
    keyBits = '{0:08b}'.format(key)
    textBits = ''.join(format(ord(i), '08b') for i in plaintext)
    repeat = math.ceil(len(textBits)/len(keyBits))
    cipherbits = ""
    if repeat>1:
        i = 0
        key_aux = key
        while i<repeat:
            key_aux = key_aux + 1
            key_aux_bits = '{0:08b}'.format(key_aux)
            keyBits = keyBits + key_aux_bits
            i+=1
    loop = min(len(keyBits), len(textBits))
    i = 0
    while i<loop:
        if textBits[i] == keyBits[i]:
            cipherbits = cipherbits + "0"
        else:
            cipherbits = cipherbits + "1"
        i+=1
    return cipherbits


# caesar_decipher(ciphertext, key)
# entrada: ciphertext: texto a desencriptar
#          key: clave a utilizar para el desencriptado
# salida: plaintext: texto desencriptado
# función análoga y complementaria a caesar().
def caesar_decipher(ciphertext, key):
    deciphertext = ""
    for letter in ciphertext:
        shifted = (ord(letter) - key)%256
        deciphertext = deciphertext + chr(shifted)
    return deciphertext


# xor_decipher(cipherbits, key)
# entrada: cipherbits: texto (en bits) a desencriptar
#          key: clave a utilizar para el desencriptado
# salida: plaintext: texto desencriptado
# función análoga y complementaria a xor().
def xor_decipher(cipherbits, key):
    keyBits = '{0:08b}'.format(key)
    repeat = math.ceil(len(textBits)/len(keyBits))
    plainbits = ""
    if repeat>1:
        i = 0
        key_aux = key
        while i<repeat:
            key_aux = key_aux + 1
            key_aux_bits = '{0:08b}'.format(key_aux)
            keyBits = keyBits + key_aux_bits
            i+=1
    loop = min(len(keyBits), len(textBits))
    i = 0
    while i<loop:
        if cipherbits[i] == keyBits[i]:
            plainbits = plainbits + "0"
        else:
            plainbits = plainbits + "1"
        i+=1
    plaintext = bin_to_string(plainbits)
    return plaintext


# caexor(plaintext, key)
# entrada: plaintext: texto que se desea encriptar
#          key: clave para encriptar el texto
# salida: ciphertext_2: texto encriptado (en binario)
# primero se crea un texto encriptado con cesar, luego este texto se encripta con xor
def caexor(plaintext, key):
    ciphertext_1 = caesar(plaintext, key)
    ciphertext_2 = xor(ciphertext_1, key)
    return ciphertext_2


# caexor_decipher(ciphertext, key)
# entrada: ciphertext: texto que se desea desencriptar
#          key: clave para desencriptar el texto
# salida: deciphertext_2: texto desencriptado
# primero se desencripta con xor, luego este texto se desencripta con cesar
def caexor_decipher(cipherbits, key):
    deciphertext_1 = xor_decipher(cipherbits, key)
    deciphertext_2 = caesar_decipher(deciphertext_1, key)
    return deciphertext_2


# text = readfile("test.txt")
# print(text)
# writefile("testpaste.txt", text)

text = "hola que tal"
key = 7
keyBits = '{0:08b}'.format(key)
textBits = ''.join(format(ord(i), '08b') for i in text)
print("texto plano: " + text + "\ntextBits = " + textBits)
print("\nkey: ", key, "\nkeyBits = " + keyBits)

ciphertext = caesar(text, key)
print("cifrado cesar = " + ciphertext)
deciphertext = caesar_decipher(ciphertext, key)
print("descifrado cesar = " + deciphertext)

xortext = xor(ciphertext, key)
print("cifrado xor del cifrado cesar = " + xortext)
print("descifrado cesar del cifrado xor del cifrado cesar = " + bin_to_string(xortext))
caexortext = caexor(text, key)
print("cifrado caexor (igual al xor del cesar) = " + caexortext)
decaexortext = caexor_decipher(caexortext, key)
print("descifrado caexor = " + decaexortext)
