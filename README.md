# 🕵️‍♂️ SEVO - Security Email Validator OSINT v1.0.0

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Category](https://img.shields.io/badge/category-OSINT-orange.svg)
![OPSEC](https://img.shields.io/badge/OPSEC-friendly-green.svg)

Una potente herramienta OSINT diseñada para la verificación, análisis de seguridad y reconocimiento de direcciones de correo electrónico. Ideal para investigadores de seguridad, analistas OSINT, profesionales de ciberseguridad y entusiastas del Bug Bounty.

## 📋 Características Principales

### Verificación de Correos
- Análisis sintáctico avanzado
- Verificación de registros MX
- Validación SMTP en tiempo real
- Detección de correos inexistentes
- Análisis de respuestas del servidor

### Análisis de Seguridad
- Puntuación de seguridad (0-100)
- Detección de SPF y política
- Análisis DMARC y nivel de aplicación
- Verificación de DKIM
- Detección de MTA-STS
- Análisis TLSRPT
- Verificación DNSSEC
- Evaluación de spoofing posible

### Características OSINT
- Fingerprinting de servidores
- Análisis de infraestructura
- Detección de protecciones
- Modo sigiloso para OPSEC
- Análisis detallado en modo verbose

## 🚀 Instalación

### Requisitos del Sistema
```bash
# Arch Linux
sudo pacman -S bind-tools openbsd-netcat coreutils bc

# Debian/Ubuntu
sudo apt install bind9-host netcat coreutils bc

# Kali Linux
sudo apt update && sudo apt install bind9-host netcat-openbsd coreutils bc
```

### Instalación Rápida
```bash
git clone https://github.com/tuuser/sevo.git
cd sevo
chmod +x sevo
./sevo --version
```

## 💡 Uso

### Sintaxis Básica
```bash
./sevo [opciones] <email>
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
./sevo usuario@dominio.com

# Análisis detallado con información de seguridad
./sevo -v usuario@dominio.com

# Modo sigiloso con delay de 2 segundos
./sevo -s -d 2 usuario@dominio.com
```

## 📊 Interpretación de Resultados

### Puntuación de Seguridad
- **80-100**: Excelente protección
- **50-79**: Protección moderada
- **0-49**: Protección débil

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
║    - SPF
║    - SPF_STRICT
║    - DMARC
║    - DMARC_ENFORCED
║    - DKIM
║    - TLSRPT
║
║ ⚠️  Vulnerabilidades Detectadas:
║    - MTA-STS no configurado
║
║ 🎯 Estado de Protecciones:
║    - SPF Estricto: ✅
║    - DMARC Enforced: ✅
║    - Spoofing Posible: ✅ NO
╚════════════════════════════════════════════════════════════════
```

## 🛡️ Características de Seguridad Analizadas

### SPF (Sender Policy Framework)
- Presencia de registro SPF
- Política (-all, ~all, ?all, +all)
- Nivel de restricción

### DMARC (Domain-based Message Authentication)
- Presencia de registro DMARC
- Política (reject, quarantine, none)
- Porcentaje de aplicación
- Nivel de enforcement

### DKIM (DomainKeys Identified Mail)
- Verificación de selectores comunes
- Detección de claves públicas
- Estado de implementación

### Protecciones Adicionales
- MTA-STS para seguridad de transporte
- TLSRPT para reportes TLS
- DNSSEC para seguridad DNS

## 🎯 Casos de Uso

### Investigaciones de Seguridad
- Validación de correos sospechosos
- Análisis de configuraciones
- Detección de vulnerabilidades

### Auditorías
- Evaluación de seguridad de correo
- Verificación de configuraciones
- Identificación de riesgos

### Bug Bounty
- Reconocimiento de objetivos
- Verificación de correos
- Análisis de infraestructura

## ⚠️ Consideraciones OPSEC

- Utilizar con VPN/Proxy cuando sea necesario
- Activar modo sigiloso para reconocimiento discreto
- Usar delays apropiados para evitar detección
- Limitar frecuencia de consultas
- Documentar hallazgos de forma segura

## 📝 Notas Legales

Esta herramienta está diseñada para uso ético y profesional en:
- Pruebas autorizadas
- Investigaciones legítimas
- Auditorías de seguridad
- Análisis de sistemas propios

El uso indebido puede estar sujeto a restricciones legales.

## 🤝 Contribución

Las contribuciones son bienvenidas:
- Reporte de bugs
- Nuevas características
- Mejoras de documentación
- Optimizaciones de código

## 📜 Licencia

Este proyecto está bajo la Licencia MIT.

---

⚡ Desarrollado con ❤️ por la comunidad OSINT

