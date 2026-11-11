"""
Entrega 1 - Criptografia assimétrica e confiança

Implementa:
  1. Geração de pares de chaves (RSA-3072 para cifragem, Ed25519 para assinatura)
  2. Cifragem híbrida: AES-256-GCM (conteúdo) + RSA-OAEP/SHA-256 (encapsulamento da chave)
  3. Assinatura digital Ed25519 (autenticidade e integridade)
  4. Demonstração de sucesso e de falha após adulteração

Dependência: pip install cryptography
Uso:         python entrega1.py
"""
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEYS_DIR = Path("keys")  # adicione "keys/" ao .gitignore!


# ---------------------------------------------------------------- chaves
def gerar_chaves():
    """Gera e salva dois pares de chaves. A chave privada é protegida por senha."""
    KEYS_DIR.mkdir(exist_ok=True)
    senha = b"senha-de-demonstracao"  # em uso real: pedir ao usuário / cofre de segredos

    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ed_priv = ed25519.Ed25519PrivateKey.generate()

    for nome, priv in (("rsa", rsa_priv), ("ed25519", ed_priv)):
        (KEYS_DIR / f"{nome}_private.pem").write_bytes(
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(senha),
            )
        )
        (KEYS_DIR / f"{nome}_public.pem").write_bytes(
            priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return senha


def carregar_privada(nome, senha):
    return serialization.load_pem_private_key(
        (KEYS_DIR / f"{nome}_private.pem").read_bytes(), password=senha
    )


def carregar_publica(nome):
    return serialization.load_pem_public_key((KEYS_DIR / f"{nome}_public.pem").read_bytes())


# ------------------------------------------------------ cifragem híbrida
OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def cifrar_hibrido(mensagem: bytes, rsa_publica):
    chave_aes = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)  # NUNCA reutilizar com a mesma chave
    texto_cifrado = AESGCM(chave_aes).encrypt(nonce, mensagem, None)  # inclui tag de 16 bytes
    chave_cifrada = rsa_publica.encrypt(chave_aes, OAEP)
    return {"chave_cifrada": chave_cifrada, "nonce": nonce, "texto_cifrado": texto_cifrado}


def decifrar_hibrido(pacote: dict, rsa_privada) -> bytes:
    chave_aes = rsa_privada.decrypt(pacote["chave_cifrada"], OAEP)
    return AESGCM(chave_aes).decrypt(pacote["nonce"], pacote["texto_cifrado"], None)


# ------------------------------------------------------ assinatura digital
def assinar(mensagem: bytes, ed_privada) -> bytes:
    return ed_privada.sign(mensagem)


def verificar(mensagem: bytes, assinatura: bytes, ed_publica) -> bool:
    try:
        ed_publica.verify(assinatura, mensagem)
        return True
    except InvalidSignature:
        return False


# ------------------------------------------------------------- demonstração
def main():
    senha = gerar_chaves()
    rsa_priv, rsa_pub = carregar_privada("rsa", senha), carregar_publica("rsa")
    ed_priv, ed_pub = carregar_privada("ed25519", senha), carregar_publica("ed25519")

    mensagem = "Transferir R$ 100,00 para a conta X (dados fictícios)".encode()
    print(f"Mensagem original: {mensagem.decode()}\n")

    # --- 1) Sigilo: cifragem híbrida
    print("== CIFRAGEM HÍBRIDA (sigilo) ==")
    pacote = cifrar_hibrido(mensagem, rsa_pub)
    print("Sucesso :", decifrar_hibrido(pacote, rsa_priv).decode())

    adulterado = dict(pacote)
    ct = bytearray(pacote["texto_cifrado"])
    ct[0] ^= 0x01  # troca 1 bit
    adulterado["texto_cifrado"] = bytes(ct)
    try:
        decifrar_hibrido(adulterado, rsa_priv)
        print("FALHA NA DEMONSTRAÇÃO: adulteração não detectada!")
    except Exception as e:
        print(f"Adulteração detectada pelo AES-GCM: {type(e).__name__}")

    # --- 2) Autenticidade: assinatura digital
    print("\n== ASSINATURA ED25519 (autenticidade e integridade) ==")
    assinatura = assinar(mensagem, ed_priv)
    print("Mensagem íntegra   ->", "assinatura VÁLIDA" if verificar(mensagem, assinatura, ed_pub) else "INVÁLIDA")

    mensagem_adulterada = mensagem.replace(b"100,00", b"900,00")
    print("Mensagem adulterada ->", "assinatura VÁLIDA" if verificar(mensagem_adulterada, assinatura, ed_pub) else "assinatura INVÁLIDA (adulteração detectada)")

    # --- 3) Impostor: assinatura com outra chave
    impostor = ed25519.Ed25519PrivateKey.generate()
    ass_falsa = assinar(mensagem, impostor)
    print("Assinatura de outra chave ->", "VÁLIDA" if verificar(mensagem, ass_falsa, ed_pub) else "INVÁLIDA (remetente não autêntico)")


if __name__ == "__main__":
    main()
