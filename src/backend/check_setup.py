#!/usr/bin/env python3
"""
🔐 GESTOR DE SENHAS - VERIFICAÇÃO DE SETUP
Executa verificações para garantir que tudo está instalado corretamente
"""

import os
import sys
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


# Cores para terminal
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def print_header():
    """Imprime header do verificador"""
    print(
        f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════╗
║   🔐 GESTOR DE SENHAS             ║
║   Verificação de Setup            ║
╚════════════════════════════════════╝
{Colors.RESET}
"""
    )


def check_python():
    """Verifica versão do Python"""
    print(f"{Colors.BLUE}[1/6]{Colors.RESET} Verificando Python...")
    try:
        version = sys.version_info
        if version.major >= 3 and version.minor >= 7:
            print(
                f"    {Colors.GREEN}✓{Colors.RESET} Python {version.major}.{version.minor}.{version.micro} encontrado"
            )
            return True
        else:
            print(f"    {Colors.RED}✗{Colors.RESET} Python 3.7+ requerido. Seu: {version.major}.{version.minor}")
            return False
    except Exception as e:
        print(f"    {Colors.RED}✗{Colors.RESET} Erro: {e}")
        return False


def check_pip():
    """Verifica se pip está instalado"""
    print(f"{Colors.BLUE}[2/6]{Colors.RESET} Verificando pip...")
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"    {Colors.GREEN}✓{Colors.RESET} pip instalado: {result.stdout.strip()}")
            return True
        else:
            print(f"    {Colors.RED}✗{Colors.RESET} pip não encontrado")
            return False
    except Exception as e:
        print(f"    {Colors.RED}✗{Colors.RESET} Erro: {e}")
        return False


def check_venv():
    """Verifica se ambiente virtual existe"""
    print(f"{Colors.BLUE}[3/6]{Colors.RESET} Verificando ambiente virtual...")
    venv_path = PROJECT_ROOT / "venv"
    if venv_path.exists():
        print(f"    {Colors.GREEN}✓{Colors.RESET} Ambiente virtual encontrado")
        return True
    else:
        print(f"    {Colors.YELLOW}⚠{Colors.RESET} Ambiente virtual NÃO encontrado")
        print("       Crie com: python -m venv venv")
        return False


def check_dependencies():
    """Verifica se dependências estão instaladas"""
    print(f"{Colors.BLUE}[4/6]{Colors.RESET} Verificando dependências...")

    required = ["flask", "flask_cors", "flask_limiter", "cryptography", "werkzeug"]
    missing = []

    for package in required:
        try:
            __import__(package.replace("_", "-").replace("-", "_"))
        except ImportError:
            missing.append(package)

    if not missing:
        print(f"    {Colors.GREEN}✓{Colors.RESET} Todas as dependências instaladas")
        return True
    else:
        print(f"    {Colors.YELLOW}⚠{Colors.RESET} Pacotes faltando: {', '.join(missing)}")
        print("       Instale com: pip install -r requirements.txt")
        return False


def check_files():
    """Verifica se arquivos principais existem"""
    print(f"{Colors.BLUE}[5/6]{Colors.RESET} Verificando arquivos...")

    required_files = [
        "src/backend/app.py",
        "src/backend/auth.py",
        "src/backend/database.py",
        "src/frontend/login.html",
        "src/frontend/register.html",
        "src/frontend/dashboard.html",
        "src/frontend/css/style.css",
        "src/frontend/js/script.js",
    ]

    missing = []
    for file in required_files:
        if not (PROJECT_ROOT / file).exists():
            missing.append(file)

    if not missing:
        print(f"    {Colors.GREEN}✓{Colors.RESET} Todos os arquivos encontrados")
        return True
    else:
        print(f"    {Colors.RED}✗{Colors.RESET} Arquivos faltando:")
        for file in missing:
            print(f"       - {file}")
        return False


def check_database():
    """Verifica se banco de dados pode ser criado"""
    print(f"{Colors.BLUE}[6/6]{Colors.RESET} Verificando banco de dados...")

    if (PROJECT_ROOT / "database.db").exists():
        print(f"    {Colors.GREEN}✓{Colors.RESET} database.db encontrado")
        return True
    else:
        print(f"    {Colors.YELLOW}⚠{Colors.RESET} database.db não encontrado")
        print("       Será criado automaticamente ao executar app.py")
        return True  # Não é erro fatal


def main():
    """Executa todas as verificações"""
    print_header()

    results = []
    results.append(("Python", check_python()))
    results.append(("pip", check_pip()))
    results.append(("Ambiente Virtual", check_venv()))
    results.append(("Dependências", check_dependencies()))
    results.append(("Arquivos", check_files()))
    results.append(("Banco de Dados", check_database()))

    print(f"\n{Colors.BOLD}{'═' * 40}{Colors.RESET}\n")
    print(f"{Colors.BOLD}Resumo da Verificação:{Colors.RESET}\n")

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = f"{Colors.GREEN}✓ OK{Colors.RESET}" if result else f"{Colors.RED}✗ FALHA{Colors.RESET}"
        print(f"  {name:20} {status}")

    print(f"\n{Colors.BOLD}{'═' * 40}{Colors.RESET}\n")

    if passed == total:
        print(f"{Colors.GREEN}{Colors.BOLD}✓ TUDO OK! Pronto para executar!{Colors.RESET}\n")
        print(f"{Colors.CYAN}Próximos passos:{Colors.RESET}")
        print("  1. python -m src.backend.run")
        print("  2. Abra: http://localhost:5000")
        print("  3. Registre-se e comece a usar!\n")
        return 0
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠ Alguns problemas encontrados!{Colors.RESET}\n")
        print(f"{Colors.CYAN}O que fazer:{Colors.RESET}")

        if not results[2][1]:  # venv
            print("  • Crie ambiente: python -m venv venv")
            print("  • Ative: .\\venv\\Scripts\\Activate.ps1 (Windows)")

        if not results[3][1]:  # dependencies
            print("  • Instale: pip install -r requirements.txt")

        if not results[4][1]:  # files
            print("  • Verifique se está na pasta correta")

        print()
        return 1


if __name__ == "__main__":
    exit_code = main()

    if exit_code == 0:
        print(f"{Colors.GREEN}Executando app.py em 3 segundos...{Colors.RESET}\n")
        import time

        time.sleep(3)

        try:
            from .app import app
            from .database import init_db

            print(f"{Colors.GREEN}✓ Aplicação iniciando...{Colors.RESET}\n")
            init_db()
            debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
            app.run(
                debug=debug,
                host=os.environ.get("HOST", "127.0.0.1"),
                port=int(os.environ.get("PORT", 5000)),
            )
        except Exception as e:
            print(f"{Colors.RED}Erro ao iniciar: {e}{Colors.RESET}")
            exit(1)
    else:
        print(f"{Colors.RED}Resolva os problemas acima e tente novamente.{Colors.RESET}\n")
        exit(1)
