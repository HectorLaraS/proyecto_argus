from __future__ import annotations

import os
from typing import Optional

import pyodbc
from dotenv import load_dotenv

load_dotenv()

# Importante: esto es global para pyodbc/ODBC y debe definirse
# antes de la primera conexión.
pyodbc.pooling = True

MSSQL_SERVER = os.getenv("MSSQL_SERVER", "").strip()
MSSQL_DATABASE = os.getenv("MSSQL_DATABASE", "ARGUS").strip()
MSSQL_USERNAME = os.getenv("MSSQL_USERNAME", "").strip()
MSSQL_PASSWORD = os.getenv("MSSQL_PASSWORD", "").strip()
MSSQL_DRIVER = os.getenv("MSSQL_DRIVER", "ODBC Driver 18 for SQL Server").strip()

MSSQL_ENCRYPT = os.getenv("MSSQL_ENCRYPT", "yes").strip()
MSSQL_TRUST_SERVER_CERT = os.getenv("MSSQL_TRUST_SERVER_CERT", "yes").strip()
MSSQL_CONNECT_TIMEOUT = int(os.getenv("MSSQL_CONNECT_TIMEOUT", "5"))


def build_connection_string(database: Optional[str] = None) -> str:
    target_db = (database or MSSQL_DATABASE).strip()

    return (
        f"DRIVER={{{MSSQL_DRIVER}}};"
        f"SERVER={MSSQL_SERVER};"
        f"DATABASE={target_db};"
        f"UID={MSSQL_USERNAME};"
        f"PWD={MSSQL_PASSWORD};"
        f"Encrypt={MSSQL_ENCRYPT};"
        f"TrustServerCertificate={MSSQL_TRUST_SERVER_CERT};"
        f"Connection Timeout={MSSQL_CONNECT_TIMEOUT};"
    )


def get_connection(database: Optional[str] = None) -> pyodbc.Connection:
    conn_str = build_connection_string(database=database)
    return pyodbc.connect(conn_str)