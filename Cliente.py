#Mauricio Caneo Catalan
#Universidad Finis Terrae
#Asignatura: Seguridad Informatica
#Profesor: Manuel Alba
#Laboratorio Evaluado N°9

#El cliente es Jonathan.
import socket
import sys
import Crypto
from Crypto import Cipher
from Crypto.PublicKey import RSA
import binascii
from Crypto.Cipher import PKCS1_OAEP
import random 
from secrets import token_bytes
from Crypto.Cipher import AES
from secrets import token_bytes

cl_socket = socket.socket()
cl_socket.connect(('localhost',8000))

while True:
    #PARTE 1
    #Escribimos el mensaje al servidor.
    mensaje = ("Conectando el cliente...")
    cl_socket.send(mensaje.encode())
    #EL CLIENTE CIFRA EL MENSAJE Y LO ENVIA AL SERVIDOR.
    #Leer Archivo txt con el mensaje a cifrar.
    #Abrir el archivo de texto.
    MensajeEntrada = open("mensajeentrada.txt","r+",encoding="utf-8")
    #Lee el texto con el mensaje.
    mensajeentrada = MensajeEntrada.read()
    #Cierra el archivo de texto.
    MensajeEntrada.close

    #Recibir clave publica generada en el servidor.
    Clave_Publica = cl_socket.recv(2048).decode()
    print("Recibiendo clave publica del servidor...")
    print("Clave publica : ", Clave_Publica)

    #Encriptar el mensaje con RSA.
    #Mensaje a cifrar.
    mensaje = mensajeentrada
    mensaje = mensaje.encode()

    #Importar clave publica.
    Clave_Publica = RSA.importKey(binascii.unhexlify(Clave_Publica))

    #Cifrado RSA.
    cifrado = PKCS1_OAEP.new(Clave_Publica)
    Mensaje_Cifrado = cifrado.encrypt(mensaje)
    print("\n")
    print("Mensaje Cifrado RSA: ",Mensaje_Cifrado)

    #Enviar el mensaje encriptado al servidor.
    cl_socket.send(Mensaje_Cifrado)

    ###############################################
    #PARTE 2
    #Recibimos la palabra inversa desde el servidor.
    Palabra_Inversa = cl_socket.recv(2048).decode()
    print("Recibiendo clave publica del servidor...")
    print("Palabra inversa : ", Palabra_Inversa)

    #Crea Llave diffie hellman (Kb).
    #Escribimos el mensaje al servidor.
    mensaje = input("Escribe un numero primo : ")
    K = input("Escribe un numero menor al anterior : ")
    #Guardamos K y P.
    P = int(mensaje)
    print("P = ",P)
    Num_K = int(K)
    print("K = ",K)
    #Genera un numero random menor a P.
    b = random.randint(1, P-1)
    #Generamos la llave para Jonathan.
    B = ((pow(int(K), b)) % P)
    print("B = ",B)
    #Enviamos mensaje que seria P.
    cl_socket.send(mensaje.encode())
    #Enviamos mensaje que seria K.
    cl_socket.send(K.encode())
    #Recibo A.
    A = cl_socket.recv(1024).decode()
    #Calculo clave secreta
    Kb = ((pow(int(A), b)) % P)
    print("CLave Secreta de Jonathan  = ",Kb)
    #Envio B desde el cliente.
    num_B = str(B)
    cl_socket.send(num_B.encode())

    #Lee el texto con el mensaje.
    #Abrir el archivo de texto.
    MensajeEntrada = open("mensajeentrada.txt","r+",encoding="utf-8")
    msg = MensajeEntrada.read()
    #Cierra el archivo de texto.
    MensajeEntrada.close

    #Enviar clave secreta del cliente al servidor.
    Clave_cliente = str(Kb) 
    cl_socket.send(Clave_cliente.encode())
    print("enviando clave Df/Hellman al servidor...")
    #AES256
    #CIFRADO
    key = token_bytes(16)

    def encrypt(msg):
        cipher = AES.new(key,AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
        return nonce, ciphertext, tag
    #AES256
    #DESCIFRADO
    def decrypt(nonce, ciphertext, tag ):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
            return(plaintext.decode('ascii'))
        except:
            return False

    nonce, ciphertext, tag = encrypt(Palabra_Inversa)
    plaintext = decrypt(nonce,ciphertext, tag)
    print(f'ciphertext: {ciphertext}')
    if not plaintext:
        print("Mensaje corrupto")
    else:
        print(f'texto plano : {plaintext}')
    ###############################################
    #Cerramos el socket del cliente.
    print("\nCerrando Socket...")
    cl_socket.close()
    sys.exit()
