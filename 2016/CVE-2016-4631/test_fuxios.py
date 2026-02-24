#!/usr/bin/env python3
"""
Suite de pruebas para FuxIOS.py v2.0
Pruebas de funcionalidad sin ejecutar el exploit real
"""

import sys
import ipaddress
from unittest.mock import Mock, patch
import os

# Agregar el directorio actual al path para importar FuxIOS
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_ip_validation():
    """Prueba la validación de direcciones IP"""
    print("🧪 Probando validación de IP...")
    
    # Importar función después de agregar al path
    try:
        from FuxIOS import validate_ip
        
        # IPs válidas
        valid_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"]
        for ip in valid_ips:
            assert validate_ip(ip), f"IP válida falló: {ip}"
            print(f"   ✅ {ip} - VÁLIDA")
        
        # IPs inválidas
        invalid_ips = ["192.168.1.256", "10.0.0", "not.an.ip", ""]
        for ip in invalid_ips:
            assert not validate_ip(ip), f"IP inválida pasó: {ip}"
            print(f"   ❌ {ip} - INVÁLIDA (correcto)")
            
        print("✅ Prueba de validación IP: PASADA")
        return True
    except Exception as e:
        print(f"❌ Error en prueba IP: {e}")
        return False

def test_subnet_validation():
    """Prueba la validación de subredes"""
    print("\n🧪 Probando validación de subred...")
    
    try:
        from FuxIOS import validate_subnet
        
        # Subredes válidas
        valid_subnets = ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/16"]
        for subnet in valid_subnets:
            assert validate_subnet(subnet), f"Subred válida falló: {subnet}"
            print(f"   ✅ {subnet} - VÁLIDA")
        
        # Subredes inválidas
        invalid_subnets = ["192.168.1.0/33", "not.a.subnet", "192.168.1.256/24"]
        for subnet in invalid_subnets:
            assert not validate_subnet(subnet), f"Subred inválida pasó: {subnet}"
            print(f"   ❌ {subnet} - INVÁLIDA (correcto)")
            
        print("✅ Prueba de validación subred: PASADA")
        return True
    except Exception as e:
        print(f"❌ Error en prueba subred: {e}")
        return False

def test_privilege_detection():
    """Prueba la detección de privilegios"""
    print("\n🧪 Probando detección de privilegios...")
    
    try:
        from FuxIOS import is_root
        
        result = is_root()
        print(f"   Privilegios detectados: {'✅ SÍ' if result else '❌ NO'}")
        print("✅ Prueba de detección privilegios: PASADA")
        return True
    except Exception as e:
        print(f"❌ Error en prueba privilegios: {e}")
        return False

def test_argument_parsing():
    """Prueba el análisis de argumentos"""
    print("\n🧪 Probando análisis de argumentos...")
    
    try:
        from FuxIOS import parse_arguments
        
        # Simular argumentos
        test_args = [
            "--source", "192.168.1.100",
            "--network", "192.168.1.0/24",
            "--max-payload", "50",
            "--delay", "0.1"
        ]
        
        with patch('sys.argv', ['FuxIOS.py'] + test_args):
            args = parse_arguments()
            
            assert args.source == "192.168.1.100"
            assert args.network == "192.168.1.0/24"
            assert args.max_payload == 50
            assert args.delay == 0.1
            
            print("   ✅ Argumentos analizados correctamente")
            print(f"      Origen: {args.source}")
            print(f"      Red: {args.network}")
            print(f"      Payload máximo: {args.max_payload}")
            print(f"      Retraso: {args.delay}")
        
        print("✅ Prueba de análisis de argumentos: PASADA")
        return True
    except Exception as e:
        print(f"❌ Error en prueba argumentos: {e}")
        return False

def test_packet_creation():
    """Prueba la creación de paquetes (sin envío)"""
    print("\n🧪 Probando creación de paquetes...")
    
    try:
        from FuxIOS import create_malicious_packet
        
        # Crear paquete de prueba
        packet = create_malicious_packet("192.168.1.95", "192.168.1.1", "x" * 10)
        
        if packet:
            print("   ✅ Paquete creado exitosamente")
            print(f"      Tipo: {type(packet)}")
            print("✅ Prueba de creación paquetes: PASADA")
            return True
        else:
            print("   ❌ Falló la creación del paquete")
            return False
    except Exception as e:
        print(f"❌ Error en prueba paquetes: {e}")
        return False

def main():
    """Ejecuta todas las pruebas"""
    print("🔬 FuxIOS.py v2.0 - Suite de Pruebas")
    print("=" * 50)
    
    tests = [
        test_ip_validation,
        test_subnet_validation,
        test_privilege_detection,
        test_argument_parsing,
        test_packet_creation
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Error en prueba: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 RESULTADOS: {passed}/{total} pruebas pasadas")
    
    if passed == total:
        print("🎉 ¡Todas las pruebas pasaron! El script está listo para usar.")
    else:
        print("⚠️  Algunas pruebas fallaron. Revisa la configuración.")
    
    print("\n💡 Para ejecutar el exploit real:")
    print("   python FuxIOS.py --help")

if __name__ == "__main__":
    main()
