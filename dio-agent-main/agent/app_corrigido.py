import hashlib
import hmac
import secrets
import sqlite3
from contextlib import closing


_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_HASH_BYTES = 64


def criar_hash_senha(senha: str) -> str:
    """Gera um hash scrypt com salt aleatório para armazenar no banco."""
    if not isinstance(senha, str) or not senha:
        raise ValueError("A senha deve ser uma string não vazia.")

    salt = secrets.token_bytes(_SALT_BYTES)
    derivada = hashlib.scrypt(
        senha.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_HASH_BYTES,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${derivada.hex()}"


def verificar_senha(senha: str, hash_armazenado: str) -> bool:
    """Valida senha sem aceitar parâmetros de custo arbitrários do banco."""
    if not isinstance(senha, str) or not isinstance(hash_armazenado, str):
        return False

    try:
        algoritmo, n, r, p, salt_hex, derivada_hex = hash_armazenado.split("$")
        salt = bytes.fromhex(salt_hex)
        derivada_esperada = bytes.fromhex(derivada_hex)
        if (
            algoritmo != "scrypt"
            or (int(n), int(r), int(p)) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
            or len(salt) != _SALT_BYTES
            or len(derivada_esperada) != _HASH_BYTES
        ):
            return False
    except (ValueError, TypeError):
        return False

    derivada_atual = hashlib.scrypt(
        senha.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_HASH_BYTES,
    )
    return hmac.compare_digest(derivada_atual, derivada_esperada)


def fazer_login(usuario: str, senha: str, caminho_banco: str = "banco_de_dados.db") -> str:
    """Autentica usando usuarios(username, password_hash) e falha de forma segura."""
    if not isinstance(usuario, str) or not isinstance(senha, str):
        return "Acesso Negado."

    try:
        with closing(sqlite3.connect(caminho_banco)) as conexao:
            cursor = conexao.cursor()
            cursor.execute(
                "SELECT password_hash FROM usuarios WHERE username = ? LIMIT 1",
                (usuario,),
            )
            resultado = cursor.fetchone()
    except sqlite3.Error:
        return "Acesso Negado."

    if resultado and verificar_senha(senha, resultado[0]):
        return "Acesso Permitido!"
    return "Acesso Negado."
