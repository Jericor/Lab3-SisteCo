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
    # Se rellena el texto con '#' en caso de ser necesario
    text = fillText(text)
    # Se pasa la llave a tipo de dato 'Bytes'
    key_byte = bytes(key, encode)
    text_cipher = ""
    # Se generan las subllaves del cifrado
    keys = subkey(key_byte)
    # Por cada bloque de 32 bits (4 carácteres del texto)
    for i in range(0, len(text), 4):
        # Se pasan ambos lados del bloque a tipo de dato 'Bytes'
        L = bytes(text[i:i + 2], encode)
        R = bytes(text[i + 2:i + 4], encode)
        # Por cada subllave se realiza un XOR entre la llave y el lado derecho
        # Y luego entre el lado izquierdo y el resultado anterior
        # Y se cambia la posición de los lados
        #print(L)
        #print(R)
        for j in range(0, 16):
            tmp = bxor(R, keys[j])
            tmp = bxor(L, tmp)
            L = R
            R = tmp
        # Se pasa el texto cifrado de bytes a carácteres nuevamente
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
    # Se pasa la llave a tipo de dato 'Bytes'
    key_byte = bytes(key, encode)
    text_decipher = ""
    # Se generan las subllaves del cifrado
    keys = subkey(key_byte)
    # Por cada bloque de 32 bits (4 carácteres del texto)
    for i in range(0, len(text_cipher), 4):
        # Se pasan ambos lados del bloque a tipo de dato 'Bytes'
        L = bytes(text_cipher[i:i+2], encode)
        R = bytes(text_cipher[i+2:i+4], encode)
        # Por cada subllave, partiendo desde la ultima, se realiza un XOR entre la llave y el lado derecho
        # Y luego entre el lado izquierdo y el resultado anterior
        # Y se cambia la posición de los lados
        for j in range(0, 16):
            tmp = bxor(R, keys[15 - j])
            tmp = bxor(L, tmp)
            R = L
            L = tmp
        # Se pasa el texto descifrado de bytes a carácteres nuevamente
        text_decipher = text_decipher + (L + R).decode(encode)
    # Se limpia el texto de '#' en caso de ser necesario
    text_decipher = unfillText(text_decipher)
    return text_decipher

# Generador de SubLlaves
# Entrada: Llave original en forma de Bytes
# Salida: Arreglo con las 16 SubLlaves
# Las subllaves se generan creando todas las combinaciones posibles de dos caracteres
# De entre los cuatro caracteres que tiene la llave original
def subkey(key):
    subkeys = []
    # Se crean todas las posibles combinaciones de dos carácteres
    # A partir de la llave original
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
    # Se toman 4 carácteres aleatorios dentro del texto a encriptar
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
    fill = "#" * (4 - fill)
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
    if fill > 0:
        text = text[:-fill]
    return text


# Calcula el efecto avalancha al cambiar un bit en la clave
# Entradas: Texto a encriptar
#           Tipo de codificación (utf-8)
# Salida: numero porcentaje de bits que cambian
# Se crea una llave y luego una segunda cambiando solo un bit de la primera
# Luego se ejecuta el cifrado y se comparan los bits uno a uno entre ambas encriptaciones
def avalancheEffect(text, encode):
    key_1 = keygen(text)
    tmp = (bytes(key_1, encode)[0]-1).to_bytes(1, "big").decode(encode)
    key_2 = tmp + key_1[1:]
    #print(key_1 + "\n" + key_2)
    cipher_1 = feistelCipher(text, key_1, encode)
    cipher_2 = feistelCipher(text, key_2, encode)
    binary_1 = ''.join(format(ord(i), '08b') for i in cipher_1)
    binary_2 = ''.join(format(ord(i), '08b') for i in cipher_2)
    same_bit = bitComparison(binary_1, binary_2)
    percentage = 100 - ((same_bit / len(binary_1)) * 100)
    return percentage

# Comparador de strings binarios
# Entradas: Dos string binarios (solo contienen 0's y 1's)
# Salida: Cantidad de Bits iguales entre ambos string
def bitComparison(str_1, str_2):
    acum = 0
    for i in range(0, len(str_1)):
        if str_1[i] == str_2[i]:
            acum = acum + 1
    return acum

# Media del efecto avalancha en 50 muestras
# Entradas: Texto a encriptar
#           Codificación
# Salida: Porcentaje medio de bits cambiados
def avalancheMean(text, encode):
    mean = 0
    for i in range(50):
        percentage = avalancheEffect(text, encode)
        mean += percentage
    mean = mean / 50
    return mean

# Codificación en caso de que se quiera cambiar
encode = "utf-8"

filename = input("Inserte nombre del archivo contenedor del mensaje: ")

text = readfile(filename)

if text:

    key = keygen(text)

    start_time = time.time()
    cipherText = feistelCipher(text, key, encode)
    cipher_time = time.time() - start_time
    print("Tiempo de encriptación: " + str(cipher_time))
    writefile("encrypted_"+ filename.split(".")[0] +".txt", cipherText)

    start_time = time.time()
    decipherText = feistelDecipher(cipherText, key, encode)
    decipher_time = time.time() - start_time
    print("Tiempo de desencriptación: " + str(decipher_time))

    writefile("desencrypted_" + filename.split(".")[0] + ".txt", decipherText)

    mean = avalancheMean(text, encode)
    print("Media de bits cambiados: " + str(mean) + "%.")
       
"""
    key = keygen(text)
    cipher = DES.new(bytes(key*2, encode), DES.MODE_OFB)
    start_time = time.time()
    msg = cipher.iv + cipher.encrypt(bytes(text, encode))
    cipher_time = time.time() - start_time
    print(cipher_time)

"""