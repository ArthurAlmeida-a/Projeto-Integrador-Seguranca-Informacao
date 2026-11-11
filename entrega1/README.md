# Entrega 1 — Criptografia assimétrica e confiança

## Objetivo
Proteger uma mensagem enviada a outro serviço (sigilo) e permitir verificar sua origem e integridade (autenticidade).

## Como executar
```bash
pip install cryptography
py entrega1.py
```
O script gera as chaves em `keys/` (não versionado), executa a cifragem híbrida e a assinatura, e imprime os cenários de sucesso e de falha.

## Algoritmos e parâmetros
| Função | Algoritmo | Parâmetros |
|---|---|---|
| Cifrar o conteúdo | AES-GCM | chave de 256 bits, nonce aleatório de 96 bits, tag de 128 bits |
| Encapsular a chave AES | RSA-OAEP | RSA de 3072 bits, e=65537, MGF1 e hash SHA-256 |
| Assinatura digital | Ed25519 | chave de 256 bits, assinatura de 64 bytes |

## Fluxo
**Cifragem híbrida:** o remetente gera uma chave AES aleatória, cifra a mensagem com AES-GCM e cifra a chave AES com a chave pública RSA do destinatário. O destinatário usa sua chave privada RSA para recuperar a chave AES e decifrar.

**Assinatura:** o remetente assina a mensagem com sua chave privada Ed25519; o destinatário verifica com a chave pública correspondente.

## Resultados da demonstração
- Mensagem íntegra: decifra e verifica com sucesso.
- Texto cifrado alterado (1 bit): o AES-GCM rejeita (`InvalidTag`).
- Mensagem alterada após assinada: a verificação falha.
- Assinatura feita por outra chave: a verificação falha.

**Demonstração** https://drive.google.com/file/d/1zA99v3gluMKyGmW76y9yWF7UFgfNjyFR/view?usp=sharing

## Sigilo × Autenticidade
- **Sigilo (confidencialidade):** só quem possui a chave correta consegue ler o conteúdo. É obtido com a cifragem (AES-GCM + RSA-OAEP).
- **Autenticidade (e integridade):** garante quem produziu a mensagem e que ela não foi modificada. É obtida com a assinatura digital.
- São propriedades independentes: uma mensagem pode ser secreta mas de origem desconhecida (cifrada com chave pública, qualquer um pode enviar), ou autêntica mas legível por todos (apenas assinada).

## Certificados digitais e PKI
Uma chave pública sozinha não prova a quem pertence. Um **certificado digital** (X.509) vincula uma chave pública a uma identidade e é assinado por uma **Autoridade Certificadora (CA)**. A **PKI** é a infraestrutura que reúne CAs, emissão, validação da cadeia de confiança, revogação (CRL/OCSP) e expiração. Neste projeto as chaves públicas são trocadas diretamente, sem PKI; em produção seriam distribuídas por certificados.

## Gestão de chaves
- Chaves geradas localmente em `keys/`, ignorada pelo Git (`.gitignore`).
- Chaves privadas gravadas em PEM/PKCS#8 cifradas por senha.
- A chave pública pode ser distribuída livremente; a privada nunca sai do dono.