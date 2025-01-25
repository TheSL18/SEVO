# 🕵️‍♂️ SEVO - Security Email Validator OSINT v2.1.0

![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-yellow.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Category](https://img.shields.io/badge/category-OSINT-orange.svg)
![OPSEC](https://img.shields.io/badge/OPSEC-friendly-green.svg)

Una potente herramienta OSINT diseñada para la verificación, análisis de seguridad y reconocimiento de direcciones de correo electrónico. Reescrita completamente en Python para mayor flexibilidad y mantenibilidad. Ideal para investigadores de seguridad, analistas OSINT, profesionales de ciberseguridad y entusiastas del Bug Bounty.

## 📋 Características Principales

### Verificación de Correos
- Análisis sintáctico avanzado con expresiones regulares
- Verificación asíncrona de registros MX
- Validación SMTP en tiempo real
- Detección de correos inexistentes
- Análisis detallado de respuestas del servidor
- Soporte para conexiones seguras

### Análisis de Seguridad Mejorado
- Sistema de puntuación de seguridad avanzado (0-100)
- Detección y análisis exhaustivo de SPF
  - Evaluación de mecanismos SPF
  - Detección de configuraciones débiles
  - Análisis de modificadores
- Análisis DMARC completo
  - Verificación de porcentaje de aplicación
  - Evaluación de políticas y modos
  - Análisis de reportes y alineación
- Verificación multi-selector de DKIM
- Análisis PTR
- Detección mejorada de susceptibilidad a spoofing
- Evaluación de fortaleza de configuración (SPF/DMARC)

### Características OSINT & OPSEC
- Fingerprinting avanzado de servidores
- Análisis de infraestructura de correo
- Detección de protecciones y vulnerabilidades
- Modo sigiloso mejorado para OPSEC
- Sistema de logging detallado
- Soporte para proxies/VPN

## 🚀 Instalación

### Requisitos del Sistema
- Python 3.7+
- pip (gestor de paquetes de Python)

### Dependencias Python
```bash
pip install -r requirements.txt
```

Las dependencias principales incluyen:
- dnspython
- rich
- asyncio

### Instalación Rápida
```bash
git clone https://condorcs.net/mrhacker/SEVO.git
cd SEVO
pip install -r requirements.txt
python sevo.py --version
```

## 💡 Uso

### Sintaxis Básica
```bash
python sevo.py [opciones] <email>
```

### Opciones Disponibles
```
-v, --verbose    Modo verbose, muestra información detallada
-s, --stealth    Modo sigiloso, más lento pero menos detectable
-d, --delay N    Añade un delay de N segundos entre consultas
-h, --help       Muestra esta ayuda
    --version    Muestra la versión
```

### Ejemplos de Uso
```bash
# Verificación básica
python sevo.py usuario@dominio.com

# Análisis detallado con información de seguridad
python sevo.py -v usuario@dominio.com

# Modo sigiloso con delay de 2 segundos
python sevo.py -s -d 2 usuario@dominio.com
```

## 📊 Interpretación de Resultados

### Puntuación de Seguridad
- **80-100**: Protección excelente (SPF estricto, DMARC enforced 100%, DKIM)
- **50-79**: Protección moderada (algunas medidas implementadas)
- **0-49**: Protección débil (configuraciones ausentes o permisivas)

### Detección de Spoofing
La herramienta analiza:
- Fortaleza de SPF (escala 0-3)
  - 3: Configuración estricta (-all)
  - 2: Configuración moderada (~all)
  - 1: Configuración débil (?all)
  - 0: Sin protección (+all)
- Fortaleza de DMARC (escala 0-3)
  - 3: Reject enforced
  - 2: Quarantine
  - 1: Modo monitoreo
  - 0: Sin DMARC
- Porcentaje de aplicación DMARC
- Configuración de reportes (RUA/RUF)
- Modos de alineación DKIM/SPF
- Validez de registros PTR
- Acumulación de vulnerabilidades

### Indicadores de Estado
| Símbolo | Significado |
|---------|-------------|
| ✅ | Verificación exitosa/Característica presente |
| ❌ | Verificación fallida/Característica ausente |
| ⚠️ | Advertencia/Riesgo potencial |
| 🔍 | Análisis en proceso |

### Ejemplo de Salida
```
╔════════════════════════════════════════════════════════════════
║ 🔒 Análisis de Seguridad para dominio.com
╠════════════════════════════════════════════════════════════════
║ 📊 Puntuación de Seguridad: 95/100
║
║ ✅ Características de Seguridad Detectadas:
║    - SPF (Strict)
║    - DMARC (Enforced)
║    - DKIM (Valid)
║    - TLSRPT (Enabled)
║    - DNSSEC (Active)
║
║ ⚠️  Vulnerabilidades Detectadas:
║    - DMARC no aplicado al 100%
║    - Falta registro PTR válido
║
║ 🎯 Estado de Protecciones:
║    - SPF Estricto: ✅
║    - DMARC Enforced: ✅
║    - Spoofing Posible: ⚠️ SÍ
╚════════════════════════════════════════════════════════════════
```

## 🛡️ Métodos de Validación

### Validación de Correo
- Verificación de sintaxis RFC 5322
- Resolución DNS asíncrona
- Validación SMTP con soporte TLS
- Análisis de respuestas del servidor
- Detección de políticas anti-spam

### Análisis de Seguridad
- Verificación exhaustiva de SPF
- Análisis de políticas DMARC
- Verificación multi-selector DKIM
- Evaluación de seguridad de transporte
- Análisis de vectores de spoofing

## ⚠️ Consideraciones OPSEC

- Utilizar siempre a través de VPN/Proxy
- Activar modo sigiloso para reconocimiento
- Implementar delays apropiados
- Respetar límites de consultas
- Mantener logs seguros

## 📝 Notas Legales

Esta herramienta está diseñada exclusivamente para uso ético y profesional en:
- Pruebas autorizadas
- Investigaciones legítimas
- Auditorías de seguridad
- Análisis de sistemas propios

El uso indebido está prohibido y puede estar sujeto a consecuencias legales.

## 🤝 Contribución

Las contribuciones son bienvenidas:
1. Fork del repositorio
2. Crear rama de características
3. Commit de cambios
4. Push a la rama
5. Crear Pull Request

## 📜 Licencia

Este proyecto está bajo la Licencia MIT.

---

⚡ Desarrollado con ❤️ por Kevin Muñoz (@MrHacker)
