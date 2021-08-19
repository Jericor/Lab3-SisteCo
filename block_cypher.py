import math
from Crypto.Util.strxor import strxor as bxor
from Crypto.Cipher import DES
import random
import time


# Leer archivo
# Entrada: nombre del archivo
# Salida: String de texto del archivo
def readfile(filename):
    try:
        with open(filename,'r') as stream:
            filetext = stream.read()
            stream.close()
    except Exception:
        filetext = 0
        print("Archivo no encontrado.")
    return filetext

# Escribir archivo
# Entradas: nombre del archivo
#           texto a escribir
# Salida: Nada (Se escribe el texto plano)
def writefile(filename, text):
    stream = open(filename, 'w')
    stream.write(text)
    stream.close()
    return

# Cifrado Feistel
# Entradas: texto a encriptar
#           llave del cifrado
#           Tipo de codificacion (utf-8)
# Salida: Texto Cifrado
# Se cifra el texto en bloques de 4 Bytes (32 Bits)
# La funcion que se realiza entre el lado derecho y la subllave es un XOR
# Y luego se hace un XOR entre el resultado anterior y el lado izquierdo del bloque
# Se hacen 16 iteraciones del proceso y se procede con el siguiente bloque
def feistelCipher(text, key, encode):
    text = fillText(text)
    key_byte = bytes(key, encode)
    text_cipher = ""
    keys = subkey(key_byte)
    for i in range(0, len(text), 4):
        L = bytes(text[i:i + 2], encode)
        R = bytes(text[i + 2:i + 4], encode)
        for j in range(0, 16):
            tmp = bxor(R, keys[j])
            tmp = bxor(L, tmp)
            L = R
            R = tmp
        text_cipher = text_cipher + (L+R).decode(encode)
    return text_cipher

# Descifrado Feistel
# Entradas: texto encriptado
#           llave del cifrado
#           Tipo de codificacion (utf-8)
# Salida: Texto Descifrado
# Se descifra el texto en bloques de 4 Bytes (32 Bits)
# La funcion que se realiza entre el lado derecho y la subllave es un XOR
# Y luego se hace un XOR entre el resultado anterior y el lado izquierdo del bloque
# Se hacen 16 iteraciones del proceso, utilizando las llaves de manera inversa,
# Y se procede con el siguiente bloque
def feistelDecipher(text_cipher, key, encode):
    key_byte = bytes(key, encode)
    text_decipher = ""
    keys = subkey(key_byte)
    for i in range(0, len(text_cipher), 4):
        L = bytes(text_cipher[i:i+2], encode)
        R = bytes(text_cipher[i+2:i+4], encode)
        for j in range(0, 16):
            tmp = bxor(R, keys[15 - j])
            tmp = bxor(L, tmp)
            R = L
            L = tmp
        text_decipher = text_decipher + (L + R).decode(encode)
    text_decipher = unfillText(text_decipher)
    return text_decipher

# Generador de SubLlaves
# Entrada: Llave original en forma de Bytes
# Salida: Arreglo con las 16 SubLlaves
# Las subllaves se generan creando todas las combinaciones posibles de dos caracteres
# De entre los cuatro caracteres que tiene la llave original
def subkey(key):
    subkeys = []
    for i in range(0,4):
        for j in range(0,4):
            subkeys.append(key[i].to_bytes(1,"big") + key[j].to_bytes(1, "big"))
    return subkeys

# Generador de Llave
# Entrada: Texto a cifrar
# Salida : Llave de encriptación
# La llave se genera a partir de 4 caracteres aleatorios dentro del mensaje a encriptar
def keygen(text):
    length = len(text)
    key = ""
    for i in range(0, 4):
        key = key + text[random.randint(0, length)]
    return key

# Rellenador de texto
# Entrada: Texto a encriptar
# Salida: Texto rellenado
# Cuando el texto no tiene una cantidad de caracteres que sea multiplo de 4
# Se le agrega un string de caracteres '#' para rellenar
def fillText(text):
    fill = len(text) % 4
    fill = "#" * fill
    text = text + fill
    return text

# Limpiador de texto
# Entrada: Texto desencriptado
# Salida: Texto desencriptado limpio (sin los '#' al final)
def unfillText(text):
    fill = 0
    for i in range(1, 4):
        if text[-i] == "#":
            fill = fill + 1
    text = text[:-fill]
    return text


def avalancheEffect(text, encode):
    key_1 = keygen(text)
    tmp = (bytes(key_1, encode)[0]-1).to_bytes(1, "big").decode(encode)
    key_2 = tmp + key_1[1:]
    print(key_1 + "\n" + key_2)
    cipher_1 = feistelCipher(text, key_1, encode)
    cipher_2 = feistelCipher(text, key_2, encode)
    binary_1 = ''.join(format(ord(i), '08b') for i in cipher_1)
    binary_2 = ''.join(format(ord(i), '08b') for i in cipher_2)
    same_bit = bitComparison(binary_1, binary_2)
    percentage = 100 - ((same_bit / len(binary_1)) * 100)
    return percentage

def bitComparison(str_1, str_2):
    acum = 0
    for i in range(0, len(str_1)):
        if str_1[i] == str_2[i]:
            acum = acum + 1
    return acum

# Codificación en caso de que se quiera cambiar
encode = "utf-8"

filename = input("Inserte nombre del archivo contenedor del mensaje: ")

text = readfile(filename)
mean = 0

for i in range(50):
    percentage = avalancheEffect(text, encode)
    mean += percentage
    print("Avalancha: ", percentage)
mean = mean/50
print("promedio: ", mean)


if text:
    
    # La llave debe ser un string de 4 caracteres
    key = keygen(text)

    start_time = time.time()
    cipherText = feistelCipher(text, key, encode)
    cipher_time = time.time() - start_time
    print(cipher_time)
    writefile("encrypted.txt", cipherText)

    start_time = time.time()
    decipherText = feistelDecipher(cipherText, key, encode)
    decipher_time = time.time() - start_time
    print(decipher_time)

    writefile("desencrypted.txt", decipherText)
       

    """"
    key = keygen(text)
    cipher = DES.new(bytes(key*2, encode), DES.MODE_OFB)
    start_time = time.time()
    msg = cipher.iv + cipher.encrypt(bytes(text, encode))
    cipher_time = time.time() - start_time
    print(cipher_time)
    """

