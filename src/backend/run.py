#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Start the Janus local password manager
Executa a aplicação Flask com configurações padrão
"""

import os
import sys
from .database import init_db
from .app import app


def main():
    """Função principal para executar a aplicação"""

    print("=" * 50)
    print("🔐 Janus")
    print("=" * 50)

    # Inicializar banco de dados
    print("\n📦 Inicializando banco de dados...")
    try:
        init_db()
        print("✓ Banco de dados inicializado com sucesso!")
    except Exception as e:
        print(f"✗ Erro ao inicializar banco de dados: {e}")
        sys.exit(1)

    # Configurações
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    print("\n🚀 Iniciando servidor...")
    print(f"   Host: http://localhost:{port}")
    print(f"   Debug: {debug}")
    print("\n✨ Pressione Ctrl+C para parar o servidor\n")
    print("=" * 50)

    try:
        app.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        print("\n\n🛑 Servidor interrompido pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Erro ao iniciar servidor: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
