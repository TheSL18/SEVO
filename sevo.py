#!/usr/bin/env python

import asyncio
import dns.resolver
import argparse
import re
import socket
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich import print as rprint

VERSION = "2.0.0"

@dataclass
class SecurityAnalysis:
    score: int
    features: List[str]
    vulnerabilities: List[str]
    spf_strict: bool
    dmarc_enforced: bool
    spoofable: bool

class Colors:
    GREEN = "\033[0;32m"
    RED = "\033[0;31m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    NC = "\033[0m"

class EmailValidator:
    def __init__(self, verbose: bool = False, stealth: bool = False, delay: int = 0):
        self.verbose = verbose
        self.stealth = stealth
        self.delay = delay
        self.console = Console()

    @staticmethod
    def show_banner():
        banner = """
    ███████╗███╗   ███╗ █████╗ ██╗██╗      ██████╗ ███████╗██╗███╗   ██╗████████╗
    ██╔════╝████╗ ████║██╔══██╗██║██║     ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
    █████╗  ██╔████╔██║███████║██║██║     ██║   ██║███████╗██║██╔██╗ ██║   ██║   
    ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║     ██║   ██║╚════██║██║██║╚██╗██║   ██║   
    ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗╚██████╔╝███████║██║██║ ╚████║   ██║   
    ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
        """
        print(f"{Colors.CYAN}{banner}{Colors.NC}")
        print(f"{Colors.CYAN} Email OSINT Validator v{VERSION}{Colors.NC}")
        print(f"{Colors.BLUE} Desarrollado por: Kevin Muñoz (MrHacker|TheSL18){Colors.NC}")
        print(f"{Colors.YELLOW} Uso ético - Solo para investigación autorizada{Colors.NC}\n")

    async def analyze_mx_security(self, domain: str) -> SecurityAnalysis:
        security_features = []
        vulnerabilities = []
        security_score = 0
        spf_strict = False
        dmarc_enforced = False
        spoofable = False

        try:
            # Check SPF
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                spf_record = next((str(record) for record in answers 
                                   if str(record).startswith('"v=spf1')), None)

                if spf_record:
                    security_features.append("SPF")
                    security_score += 20

                    if '-all' in spf_record:
                        security_features.append("SPF_STRICT")
                        spf_strict = True
                        security_score += 15
                    elif '~all' in spf_record:
                        security_features.append("SPF_SOFT_FAIL")
                        vulnerabilities.append("SPF no es estricto (usa ~all)")
                        security_score += 10
                    elif '?all' in spf_record:
                        vulnerabilities.append("SPF en modo neutral")
                        security_score += 5
                    elif '+all' in spf_record:
                        vulnerabilities.append("SPF permite cualquier remitente")
                        spoofable = True
                else:
                    vulnerabilities.append("No se encontró registro SPF")
                    spoofable = True
            except Exception as e:
                vulnerabilities.append(f"Error al verificar SPF: {str(e)}")

            # Check DMARC
            try:
                answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                dmarc_record = next((str(record) for record in answers 
                                     if str(record).startswith('"v=DMARC1')), None)

                if dmarc_record:
                    security_features.append("DMARC")
                    security_score += 20

                    if 'p=reject' in dmarc_record:
                        security_features.append("DMARC_ENFORCED")
                        dmarc_enforced = True
                        security_score += 15
                    elif 'p=quarantine' in dmarc_record:
                        security_features.append("DMARC_QUARANTINE")
                        security_score += 10
                    elif 'p=none' in dmarc_record:
                        vulnerabilities.append("DMARC en modo monitoreo")
                        security_score += 5
                else:
                    vulnerabilities.append("No se encontró registro DMARC")
                    spoofable = True
            except Exception as e:
                vulnerabilities.append(f"Error al verificar DMARC: {str(e)}")

            # Check DKIM
            dkim_selectors = ['default', 'google', 'mail', 'email', 'key1', 'selector1', 'selector2']
            dkim_found = False

            for selector in dkim_selectors:
                try:
                    dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                    security_features.append("DKIM")
                    security_score += 15
                    dkim_found = True
                    break
                except:
                    continue

            if not dkim_found:
                vulnerabilities.append("No se encontró registro DKIM")

        except Exception as e:
            vulnerabilities.append(f"Error en análisis de seguridad: {str(e)}")

        return SecurityAnalysis(
                score=security_score,
                features=security_features,
                vulnerabilities=vulnerabilities,
                spf_strict=spf_strict,
                dmarc_enforced=dmarc_enforced,
                spoofable=spoofable
                )

    def fingerprint_server(self, response: str) -> Optional[str]:
        server_info = re.search(r'^220.*$', response, re.MULTILINE | re.IGNORECASE)
        if not server_info:
            return None

        server_info = server_info.group(0)

        if 'mx.google.com' in server_info.lower() or 'gmail-smtp' in server_info.lower():
            return "Google Mail Infrastructure"
        elif 'microsoft' in server_info.lower():
            return "Microsoft Exchange/Office 365"
        elif 'postfix' in server_info.lower():
            return "Postfix"
        elif 'exim' in server_info.lower():
            return "Exim"
        elif 'sendmail' in server_info.lower():
            return "Sendmail"
        elif 'zimbra' in server_info.lower():
            return "Zimbra"

        return "Unknown Server"

    async def validate_email(self, email: str) -> bool:
        if not re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email):
            rprint("[red]❌ Formato de correo inválido[/]")
            return False

        rprint("[green]✓ La sintaxis del correo es correcta[/]")

        domain = email.split('@')[1]

        try:
            rprint("[cyan]🔍 Buscando registros MX...[/]")
            mx_records = sorted(
                    [(rdata.preference, rdata.exchange.to_text().rstrip('.')) 
                     for rdata in dns.resolver.resolve(domain, 'MX')],
                    key=lambda x: x[0]
                    )

            if not mx_records:
                rprint(f"[red]❌ No se encontraron registros MX para {domain}[/]")
                return False

            for preference, server in mx_records:
                rprint(f"[green]✓ MX record encontrado: {server} (Prioridad {preference})[/]")

            if self.verbose:
                security_analysis = await self.analyze_mx_security(domain)
                self.display_security_analysis(domain, security_analysis)

            primary_mx = mx_records[0][1]

            if self.stealth:
                time.sleep(self.delay)

            rprint(f"[cyan]⏳ Iniciando diálogo con {primary_mx}[/]")

            try:
                with socket.create_connection((primary_mx, 25), timeout=10) as sock:
                    sock.settimeout(10)

                    response = sock.recv(1024).decode()
                    if self.verbose:
                        server_type = self.fingerprint_server(response)
                        if server_type:
                            rprint(f"[blue]ℹ Servidor detectado: {server_type}[/]")

                    commands = [
                            f"HELO email-validator-osint.local\r\n",
                            f"MAIL FROM:<validator@email-validator-osint.local>\r\n",
                            f"RCPT TO:<{email}>\r\n",
                            "QUIT\r\n"
                            ]

                    for cmd in commands:
                        sock.send(cmd.encode())
                        response = sock.recv(1024).decode()

                        if self.verbose:
                            rprint(f"[cyan]→ {cmd.strip()}[/]")
                            rprint(f"[cyan]← {response.strip()}[/]")

                        code = response[:3]
                        if code == "550":
                            rprint(f"[red]❌ El correo {email} no es válido[/]")
                            return False
                        elif code not in ["220", "250", "221"]:
                            rprint(f"[yellow]⚠ Respuesta inesperada del servidor: {response.strip()}[/]")
                            return False

                    rprint(f"[green]✓ El correo {email} es válido[/]")
                    return True

            except Exception as e:
                rprint(f"[red]❌ Error al conectar con el servidor: {str(e)}[/]")
                return False

        except Exception as e:
            rprint(f"[red]❌ Error: {str(e)}[/]")
            return False

    def display_security_analysis(self, domain: str, analysis: SecurityAnalysis):
        table = Table(title=f"🔒 Análisis de Seguridad para {domain}")

        table.add_column("Categoría", style="cyan")
        table.add_column("Detalle", style="white")

        table.add_row(
                "📊 Puntuación de Seguridad",
                f"{analysis.score}/100"
                )

        if analysis.features:
            table.add_row(
                    "✅ Características de Seguridad",
                    "\n".join(analysis.features)
                    )

        if analysis.vulnerabilities:
            table.add_row(
                    "⚠️ Vulnerabilidades",
                    "\n".join(analysis.vulnerabilities)
                    )

        table.add_row(
                "🎯 Estado de Protecciones",
                f"SPF Estricto: {'✅' if analysis.spf_strict else '❌'}\n"
                f"DMARC Enforced: {'✅' if analysis.dmarc_enforced else '❌'}\n"
                f"Spoofing Posible: {'⚠️ SÍ' if analysis.spoofable else '✅ NO'}"
                )

        self.console.print(table)

async def main():
    parser = argparse.ArgumentParser(description='Email OSINT Validator')
    parser.add_argument('email', help='Email to validate')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    parser.add_argument('-s', '--stealth', action='store_true', help='Stealth mode')
    parser.add_argument('-d', '--delay', type=int, default=0, help='Delay between queries')
    args = parser.parse_args()

    validator = EmailValidator(verbose=args.verbose, stealth=args.stealth, delay=args.delay)
    validator.show_banner()

    result = await validator.validate_email(args.email)
    sys.exit(0 if result else 1)

if __name__ == "__main__":
    asyncio.run(main())
