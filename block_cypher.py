import math
from Crypto.Util.strxor import strxor as bxor

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

# Codificación en caso de que se quiera cambiar
encode = "utf-8"

# De momento el programa solo puede encriptar textos con una cantidad de caracteres igual a un multiplo de 4
text = "hola test tx"

# La llave debe ser un string de 4 caracteres
## Falta crear una función que pueda generar una llave aleatoria ##
key = "d9f6"

print(text)

cipherText = feistelCipher(text, key, encode)

print(cipherText)

decipherText = feistelDecipher(cipherText, key, encode)

print(decipherText)