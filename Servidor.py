#Mauricio Caneo Catalan
#Universidad Finis Terrae
#Asignatura: Seguridad Informatica
#Profesor: Manuel Alba
#Laboratorio Evaluado N°9

#El servidor es Mauricio.
import random
import socket
import sys
import Crypto
from Crypto import Cipher
from Crypto.PublicKey import RSA
import binascii
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes
from Crypto.Cipher import AES
from secrets import token_bytes

sv_socket = socket.socket()
sv_socket.bind(('localhost',8000))
sv_socket.listen()

while True:
    #PARTE 1
    #Se establece la conexion con el cliente.
    conexion, direccion = sv_socket.accept()
    print("Conectado con el cliente", direccion)

    #Recibimos el mensaje del cliente.
    mensaje = conexion.recv(1024).decode()
    print(mensaje)

    #EL SERVIDOR DECIFRA EL MENSAJE ENCRIPTADO DEL CLIENTE.
    #Generar numero aleatorio.
    random_n = Crypto.Random.new().read
    #Generar LLave Privada.
    Clave_Privada = RSA.generate(2048,random_n)
    #Generar LLave Publica.
    Clave_Publica = Clave_Privada.public_key()
    #Exportar llaves.
    Clave_Privada = Clave_Privada.exportKey(format="DER")
    Clave_Publica = Clave_Publica.exportKey(format="DER")
    #Convertir llaves de BIN a UTF8.
    Clave_Privada = binascii.hexlify(Clave_Privada).decode("utf8")
    Clave_Publica = binascii.hexlify(Clave_Publica).decode("utf8")
    print("Enviando Clave publica al cliente...")
    conexion.send(Clave_Publica.encode())
    print("Clave Publica :",Clave_Publica)
    #Importar llaves.
    Clave_Privada = RSA.importKey(binascii.unhexlify(Clave_Privada))
    Clave_Publica = RSA.importKey(binascii.unhexlify(Clave_Publica))

    #Recibe el mensaje cifrado.
    Mensaje_Cifrado = conexion.recv(2048)
    print("Recibiendo mensaje cifrado desde el cliente...")
    
    #Decifrado RSA
    Decifrado = PKCS1_OAEP.new(Clave_Privada)
    Mensaje_Decifrado = Decifrado.decrypt(Mensaje_Cifrado)
    print("\n")
    
    #String reversa
    Mensaje_Inverso = list(reversed(Mensaje_Decifrado.decode()))

    #Lista a palabra
    Palabra = (''.join(Mensaje_Inverso))

    #Guardar el mensaje decifrado en un archivo txt.
    mensajeSalida = open("mensajerecibido.txt","w+",encoding="utf-8")
    mensajeSalida.write(Palabra)
    mensajeSalida.close()
    print("Mensaje Descifrado y guardado con exito :D...")
    ###############################################
    #PARTE 2
    #Devolver el mensaje al cliente.
    print("Enviando archivo de salida.txt...")
    conexion.send(Palabra.encode())

     #Recibimos el numero P del cliente.
    MensajeR = conexion.recv(1024).decode()
    #Guardamos el numero recibido en la variable P.
    P = int(MensajeR)
    print("P = ",P)
    #Recibimos el numero K del cliente.
    MensajeK = conexion.recv(1024).decode() 
    #Guardamos el numero recibido en la variable K.
    K = int(MensajeK)
    print("K = ",K)
    #Genera un numero random menor a P.
    a = random.randint(1, P-1)
    #Generamos la llave para Mauricio.
    A = ((pow(K, a)) % P) 
    #Envio A.
    print("A = ", A)
    num_A = str(A)
    conexion.send(num_A.encode())
    #Recibo B desde del cliente.
    B = conexion.recv(1024).decode()
    #Calculo clave secreta.
    Ka = ((pow(int(B), a)) % P)
    print("CLave Secreta de Mauricio  = ",Ka)

    print("Leyendo clave secreta del cliente...")
    #Leer clave secreta del cliente.
    ciphertext = conexion.recv(1024).decode()
    print("Clave secreta Cliente : ", ciphertext)
    print("Clave secreta Servidor : ", Ka)

    
    ###############################################
    print("\nDesconectado el cliente", direccion)
    #Cerramos conexion.
    conexion.close()
    sys.exit()
