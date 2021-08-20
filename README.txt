Al ejecutar el programa se pedirá el nombre de un archivo de texto plano que 
se encuentre en la misma carpeta que el código en cuestión

Si el archivo no se encuentra el programa terminará

Si el archivo es encontrado el programa hará un cifrado y descifrado del 
texto presente en el archivo indicado, mostrando el tiempo que tomó 
el proceso de encriptación y desencriptación.

El programa generará dos archivos, "encrypted_<Filename>.txt" contiene el 
texto plano correspondiente al texto cifrado, y "desencrypted_<Filename>.txt"
muestra el mensaje despues de haber sido desencriptado.

Posterior a lo anterior se realiza una prueba del efecto avalancha producido
por el algoritmo de encriptación. (realiza 50 iteraciones, por lo cual puede
demorar en terminar el proceso.)