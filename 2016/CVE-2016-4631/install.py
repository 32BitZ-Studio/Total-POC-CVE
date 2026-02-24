#!/usr/bin/env python3
"""
Script de instalación y verificación para FuxIOS.py v2.0
"""

import sys
import subprocess
import platform
import os

def check_python_version():
    """Verifica la versión de Python"""
    if sys.version_info < (3, 7):
        print("❌ Error: Se requiere Python 3.7 o superior")
        print(f"Versión actual: {sys.version}")
        return False
    print(f"✅ Python {sys.version.split()[0]} - OK")
    return True

def check_admin_privileges():
    """Verifica privilegios de administrador"""
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print("✅ Privilegios de administrador - OK")
            else:
                print("⚠️  Advertencia: No tienes privilegios de administrador")
                print("   Ejecuta como administrador para usar el exploit")
            return is_admin
        except:
            return False
    else:
        try:
            is_root = os.geteuid() == 0
        except AttributeError:
            # geteuid no existe en Windows
            is_root = False
        if is_root:
            print("✅ Privilegios root - OK")
        else:
            print("⚠️  Advertencia: No tienes privilegios root")
            print("   Ejecuta con sudo para usar el exploit")
        return is_root

def install_package(package):
    """Instala un paquete de Python"""
    try:
        print(f"📦 Instalando {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✅ {package} instalado correctamente")
        return True
    except subprocess.CalledProcessError:
        print(f"❌ Error instalando {package}")
        return False

def check_nmap():
    """Verifica si nmap está instalado"""
    try:
        result = subprocess.run(["nmap", "--version"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version = result.stdout.split('\n')[0]
            print(f"✅ {version} - OK")
            return True
        else:
            print("❌ nmap no encontrado")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("❌ nmap no está instalado")
        print("📋 Instalar nmap:")
        if platform.system() == "Windows":
            print("   - Descarga desde: https://nmap.org/download.html")
        elif platform.system() == "Darwin":  # macOS
            print("   - brew install nmap")
        else:  # Linux
            print("   - sudo apt-get install nmap  (Ubuntu/Debian)")
            print("   - sudo yum install nmap      (CentOS/RHEL)")
        return False

def main():
    print("🔧 FuxIOS.py v2.0 - Script de Instalación")
    print("=" * 50)
    
    # Verificar Python
    if not check_python_version():
        sys.exit(1)
    
    # Verificar privilegios
    check_admin_privileges()
    
    # Verificar nmap
    nmap_ok = check_nmap()
    
    # Instalar dependencias Python
    print("\n📦 Instalando dependencias de Python...")
    packages = ["scapy", "python-nmap"]
    
    all_installed = True
    for package in packages:
        if not install_package(package):
            all_installed = False
    
    print("\n" + "=" * 50)
    print("📋 RESUMEN DE INSTALACIÓN")
    print("=" * 50)
    
    if all_installed and nmap_ok:
        print("✅ ¡Instalación completada exitosamente!")
        print("🚀 Puedes ejecutar FuxIOS.py con:")
        if platform.system() == "Windows":
            print("   python FuxIOS.py -h")
        else:
            print("   sudo python3 FuxIOS.py -h")
    else:
        print("⚠️  Instalación completada con advertencias")
        if not nmap_ok:
            print("❌ nmap necesita ser instalado manualmente")
        if not all_installed:
            print("❌ Algunas dependencias de Python fallaron")
    
    print("\n📚 Para ver la ayuda completa:")
    print("   python3 FuxIOS.py --help")

if __name__ == "__main__":
    main()
