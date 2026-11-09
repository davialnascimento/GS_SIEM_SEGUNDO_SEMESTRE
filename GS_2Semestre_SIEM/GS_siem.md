# Trabalho Final — SIEM Simplificado (SecuraPy)

| | |
|---|---|
| **Disciplina:** | Coding for Security |
| **Tipo:** | Trabalho Final Prático — Projeto em Grupo |
| **Equipe:** | 3 a 4 integrantes |
| **Peso:** | 40% da nota final |
| **Entrega:** | Código-fonte + Documentação + Apresentação |

---

## 1. Cenário

A empresa **CyberShield Ltda.**, uma consultoria de segurança da informação, foi contratada por um cliente do setor financeiro para desenvolver um **SIEM simplificado** (Security Information and Event Management) — uma ferramenta capaz de coletar, analisar e correlacionar eventos de segurança de múltiplas fontes em tempo real.

O cliente possui uma infraestrutura com servidores web, bancos de dados e firewalls que geram logs continuamente. Atualmente, a equipe de SOC (Security Operations Center) analisa esses logs manualmente, o que é lento, propenso a erros e impossibilita a detecção de ataques em andamento.

O sistema solicitado, batizado internamente de **SecuraPy**, deve:

1. Ler e interpretar logs de diferentes fontes
2. Aplicar regras de detecção configuráveis
3. Identificar padrões de ataque automaticamente
4. Alertar a equipe de segurança em tempo real via rede
5. Enriquecer eventos com informações externas de threat intelligence
6. Apresentar relatórios e permitir consultas interativas

A equipe de vocês é o time de desenvolvimento da CyberShield. O cliente espera um **MVP (Minimum Viable Product)** funcional, com código modularizado, tratamento robusto de erros e documentação clara.

---

## 2. Arquitetura do Sistema

O sistema deve ser organizado nos seguintes módulos (cada um em seu próprio arquivo `.py`):

```
securaPy/
├── main.py                 # Ponto de entrada e menu principal
├── coletor.py              # Módulo 1 — Leitura e parsing de logs
├── regras.py               # Módulo 2 — Motor de regras de detecção
├── detector.py             # Módulo 3 — Detecção de anomalias e ataques
├── servidor_alertas.py     # Módulo 4 — Servidor TCP de alertas em tempo real
├── cliente_alertas.py      # Módulo 4 — Cliente TCP que recebe alertas
├── enriquecimento.py       # Módulo 5 — Consulta a APIs de threat intelligence
├── relatorios.py           # Módulo 6 — Dashboard CLI e geração de relatórios
├── logs/                   # Pasta com arquivos de log para teste
│   ├── auth.log
│   ├── firewall.log
│   └── web_access.log
├── config/
│   └── regras.json         # Arquivo de configuração de regras
├── saida/                  # Pasta para relatórios gerados
│   └── (relatórios gerados pelo sistema)
└── README.md               # Documentação do projeto
```

> **Referência na apostila:** A criação de módulos próprios e a organização com `import` estão na **Aula 11, Seção 11.5** — lá vocês encontram o padrão de como criar um arquivo `.py` com funções e importá-lo em outro arquivo usando `from modulo import funcao`.

---

## 3. Requisitos Detalhados

---

### MÓDULO 1 — Coletor de Logs (`coletor.py`)

#### Contexto

O coletor é a base de todo SIEM. Em um ambiente real, logs chegam de dezenas de fontes em formatos diferentes — firewalls falam de uma forma, servidores web de outra, sistemas de autenticação de outra. O coletor precisa ler esses arquivos, entender o formato de cada um e transformar tudo em um formato padronizado (evento normalizado) para que o resto do sistema consiga trabalhar.

Sem essa normalização, cada módulo precisaria entender todos os formatos de log — o que seria inviável. O coletor abstrai essa complexidade: ele lê o "idioma" de cada fonte e traduz para um "idioma único" que o SIEM inteiro entende.

#### Requisitos Funcionais

1. **Ler arquivos de log** das três fontes (auth.log, firewall.log, web_access.log)
2. **Parsear cada linha** extraindo os campos relevantes (data, hora, tipo de evento, IP, etc.)
3. **Normalizar os eventos** em um formato de dicionário padronizado:
   ```python
   evento = {
       "timestamp": "2025-02-20 08:15:01",
       "fonte": "auth",           # auth | firewall | web
       "tipo": "FAIL",            # OK | FAIL | BLOCK | ALLOW | REQUEST
       "ip": "185.220.101.1",
       "detalhes": "usuario=admin",
       "linha_original": "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"
   }
   ```
4. **Tratar erros** de leitura: arquivo inexistente, linha com formato inválido, arquivo vazio
5. **Retornar uma lista** com todos os eventos normalizados de todos os arquivos

#### Funções Esperadas

```python
def carregar_log(caminho_arquivo, fonte):
    """
    Lê um arquivo de log e retorna lista de eventos normalizados.
    - caminho_arquivo: str com o path do arquivo
    - fonte: str indicando o tipo ("auth", "firewall", "web")
    - Retorna: list[dict] com os eventos parseados
    """

def parsear_linha_auth(linha):
    """Parseia uma linha do auth.log e retorna dict normalizado."""

def parsear_linha_firewall(linha):
    """Parseia uma linha do firewall.log e retorna dict normalizado."""

def parsear_linha_web(linha):
    """Parseia uma linha do web_access.log e retorna dict normalizado."""

def carregar_todos_os_logs(pasta_logs):
    """
    Lê todos os arquivos de log da pasta e retorna lista unificada.
    Usa os.listdir() para encontrar os arquivos.
    """
```

#### Dados de Teste

Crie os seguintes arquivos na pasta `logs/`:

**`logs/auth.log`** — Log de autenticação (formato: `TIMESTAMP TIPO usuario=NOME ip=IP`):
```log
2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1
2025-02-20 08:15:02 FAIL usuario=root ip=185.220.101.1
2025-02-20 08:15:03 OK usuario=carlos ip=192.168.1.10
2025-02-20 08:15:05 FAIL usuario=admin ip=91.240.118.172
2025-02-20 08:15:06 FAIL usuario=test ip=185.220.101.1
2025-02-20 08:15:08 FAIL usuario=admin ip=185.220.101.1
2025-02-20 08:15:10 OK usuario=ana ip=192.168.1.45
2025-02-20 08:15:12 FAIL usuario=root ip=91.240.118.172
2025-02-20 08:15:15 FAIL usuario=admin ip=45.33.32.156
2025-02-20 08:15:16 FAIL usuario=admin ip=185.220.101.1
2025-02-20 08:15:18 FAIL usuario=root ip=185.220.101.1
2025-02-20 08:15:20 FAIL usuario=guest ip=91.240.118.172
2025-02-20 08:15:22 FAIL usuario=admin ip=185.220.101.1
2025-02-20 08:15:25 OK usuario=bruno ip=10.0.0.5
2025-02-20 08:15:28 FAIL usuario=sa ip=185.220.101.1
2025-02-20 08:15:30 FAIL usuario=admin ip=91.240.118.172
2025-02-20 08:15:33 FAIL usuario=root ip=185.220.101.1
2025-02-20 08:15:35 FAIL usuario=test ip=45.33.32.156
2025-02-20 08:15:38 FAIL usuario=admin ip=185.220.101.1
2025-02-20 08:15:40 FAIL usuario=root ip=185.220.101.1
2025-02-20 08:15:42 OK usuario=diana ip=192.168.1.20
2025-02-20 08:15:45 FAIL usuario=admin ip=91.240.118.172
2025-02-20 08:15:48 FAIL usuario=oracle ip=45.33.32.156
```

**`logs/firewall.log`** — Log de firewall (formato: `TIMESTAMP ACAO proto=PROTO src=IP dst=IP dport=PORTA`):
```log
2025-02-20 08:10:01 ALLOW proto=TCP src=192.168.1.10 dst=10.0.0.1 dport=443
2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22
2025-02-20 08:10:03 ALLOW proto=TCP src=192.168.1.45 dst=10.0.0.1 dport=80
2025-02-20 08:10:05 BLOCK proto=TCP src=91.240.118.172 dst=10.0.0.1 dport=3389
2025-02-20 08:10:06 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=23
2025-02-20 08:10:08 ALLOW proto=UDP src=192.168.1.10 dst=8.8.8.8 dport=53
2025-02-20 08:10:10 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=445
2025-02-20 08:10:12 BLOCK proto=TCP src=45.33.32.156 dst=10.0.0.1 dport=1433
2025-02-20 08:10:15 ALLOW proto=TCP src=192.168.1.20 dst=10.0.0.1 dport=443
2025-02-20 08:10:18 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=8080
2025-02-20 08:10:20 BLOCK proto=TCP src=91.240.118.172 dst=10.0.0.1 dport=22
2025-02-20 08:10:22 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=3306
2025-02-20 08:10:25 ALLOW proto=TCP src=10.0.0.5 dst=10.0.0.1 dport=80
2025-02-20 08:10:28 BLOCK proto=TCP src=45.33.32.156 dst=10.0.0.1 dport=5432
2025-02-20 08:10:30 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=21
2025-02-20 08:10:33 BLOCK proto=TCP src=91.240.118.172 dst=10.0.0.1 dport=445
2025-02-20 08:10:35 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=139
```

**`logs/web_access.log`** — Log de acesso web (formato: `TIMESTAMP METODO url=URL ip=IP status=CODIGO`):
```log
2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200
2025-02-20 08:20:02 GET url=/login ip=185.220.101.1 status=200
2025-02-20 08:20:03 POST url=/login ip=185.220.101.1 status=401
2025-02-20 08:20:04 POST url=/login ip=185.220.101.1 status=401
2025-02-20 08:20:05 POST url=/login ip=185.220.101.1 status=401
2025-02-20 08:20:06 GET url=/admin ip=185.220.101.1 status=403
2025-02-20 08:20:08 GET url=/../../etc/passwd ip=91.240.118.172 status=400
2025-02-20 08:20:10 GET url=/index.html ip=192.168.1.45 status=200
2025-02-20 08:20:12 POST url=/api/users ip=192.168.1.10 status=201
2025-02-20 08:20:15 GET url=/search?q=<script>alert(1)</script> ip=45.33.32.156 status=400
2025-02-20 08:20:18 GET url=/wp-admin ip=91.240.118.172 status=404
2025-02-20 08:20:20 GET url=/phpmyadmin ip=91.240.118.172 status=404
2025-02-20 08:20:22 POST url=/login ip=185.220.101.1 status=401
2025-02-20 08:20:25 GET url=/api/data ip=192.168.1.20 status=200
2025-02-20 08:20:28 GET url=/shell.php ip=45.33.32.156 status=404
2025-02-20 08:20:30 POST url=/upload ip=45.33.32.156 status=403
2025-02-20 08:20:33 GET url=/robots.txt ip=10.0.0.5 status=200
2025-02-20 08:20:35 DELETE url=/api/users/1 ip=185.220.101.1 status=403
```

#### Cenários de Teste

| # | Cenário | Resultado Esperado |
|---|---------|-------------------|
| 1 | Carregar `auth.log` | Lista com 23 eventos, cada um com todos os campos preenchidos |
| 2 | Carregar arquivo inexistente `logs/naoexiste.log` | Mensagem de erro amigável, retorna lista vazia, programa **não** trava |
| 3 | Inserir uma linha mal formatada no meio do `auth.log` (ex: `linha sem formato`) | Linha ignorada com warning no console, demais linhas processadas normalmente |
| 4 | Carregar todos os logs da pasta `logs/` | Lista unificada com eventos das 3 fontes, campo `fonte` correto em cada |
| 5 | Arquivo de log vazio | Mensagem informativa, retorna lista vazia |

#### Dicas de Implementação

- **Leitura de arquivos:** Use `with open(caminho, "r") as f:` e itere com `for linha in f:` — **Aula 12, Seção 12.2**
- **Parsing de strings:** Use `linha.strip()` para remover `\n` e `linha.split()` para separar por espaços — **Aula 3, Seção 3.3** (métodos de string)
- **Extrair campos chave=valor:** Para parsear `usuario=admin`, use `campo.split("=")` que retorna `["usuario", "admin"]` — combine com o que viram em **Aula 7, Seção 7.1** (listas e indexação)
- **Tratamento de erros:** Envolva a abertura do arquivo em `try/except FileNotFoundError` — **Aula 8, Seção 8.2**
- **Listar arquivos da pasta:** Use `os.listdir(pasta)` — **Aula 11, Seção 11.2**
- **Dicionários:** Cada evento vira um dict com chaves padronizadas — **Aula 7, Seção 7.3**

---

### MÓDULO 2 — Motor de Regras (`regras.py`)

#### Contexto

Em um SIEM real, as regras de detecção são o cérebro do sistema. Uma regra define o que é considerado "suspeito" — por exemplo, "mais de 5 tentativas de login falhas do mesmo IP em 1 minuto é um ataque de brute force". Sem regras, o SIEM é apenas um leitor de logs; com regras, ele se torna um detector de ameaças.

As regras devem ser **configuráveis** — armazenadas em um arquivo JSON externo — porque o analista de segurança precisa poder ajustar os parâmetros sem mexer no código. Hoje o threshold de brute force é 5 tentativas, amanhã pode ser 10. O código não deve precisar mudar.

#### Requisitos Funcionais

1. **Carregar regras** de um arquivo JSON de configuração
2. **Aplicar cada regra** a cada evento, retornando alertas quando a regra é violada
3. **Classificar severidade** dos alertas: `CRITICA`, `ALTA`, `MEDIA`, `BAIXA`, `INFO`
4. **Suportar no mínimo 5 regras** diferentes (veja abaixo)
5. **Permitir ativar/desativar regras** sem alterar o código

#### Funções Esperadas

```python
def carregar_regras(caminho_config):
    """
    Lê o arquivo regras.json e retorna lista de dicionários de regras.
    Trata: arquivo não encontrado, JSON inválido.
    """

def aplicar_regras(eventos, regras):
    """
    Recebe lista de eventos e lista de regras.
    Retorna lista de alertas gerados.
    Cada alerta é um dict com: timestamp, regra, severidade, ip, descricao.
    """

def classificar_severidade(pontuacao):
    """
    Recebe pontuação numérica e retorna string de severidade.
    >= 9: CRITICA, >= 7: ALTA, >= 5: MEDIA, >= 3: BAIXA, < 3: INFO
    """

def avaliar_regra(regra, evento):
    """
    Avalia se um evento viola uma regra específica.
    Retorna dict de alerta ou None.
    """
```

#### Arquivo de Configuração

Crie o arquivo **`config/regras.json`**:

```json
{
    "regras": [
        {
            "id": "R001",
            "nome": "Login com Usuário Privilegiado",
            "descricao": "Tentativa de login com usuário root, admin, sa ou oracle",
            "fonte": "auth",
            "condicao": "usuario_privilegiado",
            "usuarios_alvo": ["root", "admin", "sa", "oracle", "administrator"],
            "severidade_base": 6,
            "ativa": true
        },
        {
            "id": "R002",
            "nome": "Acesso a Porta Crítica Bloqueado",
            "descricao": "Firewall bloqueou acesso a portas sensíveis",
            "fonte": "firewall",
            "condicao": "porta_critica",
            "portas_criticas": [22, 23, 3389, 445, 3306, 5432, 1433],
            "severidade_base": 7,
            "ativa": true
        },
        {
            "id": "R003",
            "nome": "Tentativa de Path Traversal",
            "descricao": "URL contém padrões de path traversal (../)",
            "fonte": "web",
            "condicao": "path_traversal",
            "padroes": ["../", "..\\", "/etc/passwd", "/etc/shadow"],
            "severidade_base": 9,
            "ativa": true
        },
        {
            "id": "R004",
            "nome": "Tentativa de XSS",
            "descricao": "URL contém padrões de Cross-Site Scripting",
            "fonte": "web",
            "condicao": "xss",
            "padroes": ["<script>", "javascript:", "onerror=", "onload="],
            "severidade_base": 8,
            "ativa": true
        },
        {
            "id": "R005",
            "nome": "Reconhecimento Web",
            "descricao": "Acesso a URLs comuns de reconhecimento/enumeração",
            "fonte": "web",
            "condicao": "reconhecimento",
            "urls_suspeitas": ["/wp-admin", "/phpmyadmin", "/shell.php", "/.env", "/admin", "/wp-login.php"],
            "severidade_base": 5,
            "ativa": true
        }
    ]
}
```

#### Cenários de Teste

| # | Cenário | Resultado Esperado |
|---|---------|-------------------|
| 1 | Evento `FAIL usuario=admin` processado contra regra R001 | Gera alerta com severidade MEDIA (6 pontos) |
| 2 | Evento `BLOCK dport=22` processado contra regra R002 | Gera alerta com severidade ALTA (7 pontos) |
| 3 | Evento `GET url=/../../etc/passwd` contra regra R003 | Gera alerta com severidade CRITICA (9 pontos) |
| 4 | Evento `GET url=/index.html` de IP interno | Nenhuma regra disparada, nenhum alerta |
| 5 | Regra R004 com `"ativa": false` no JSON | Regra ignorada, nenhum alerta mesmo com XSS |
| 6 | Arquivo `regras.json` com JSON malformado | Mensagem de erro, programa usa regras padrão ou avisa o operador |

#### Dicas de Implementação

- **Ler JSON:** Use `json.load()` com `with open()` — **Aula 14** (seção sobre JSON, `json.load` e `json.dump`)
- **Condicionais para cada regra:** Use `if regra["condicao"] == "usuario_privilegiado":` e dentro verifique com `if usuario in regra["usuarios_alvo"]:` — **Aula 4, Seção 4.3** (if-elif-else)
- **Verificar padrões na URL:** Use `any(padrao in url for padrao in regra["padroes"])` — **Aula 10, Seção 10.5** (uso de `any()` no exemplo de verificar_senha)
- **Classificar severidade:** Use um dicionário de mapeamento ou if-elif — **Aula 4** + **Aula 7, Seção 7.3** (dict como tabela de lookup)
- **Filtrar regras ativas:** Use list comprehension `[r for r in regras if r["ativa"]]` — **Aula 7, Seção 7.1** (list comprehension)
- **Tuplas para thresholds imutáveis:** Os limites de severidade podem ser definidos como tuplas — **Aula 7, Seção 7.2**

---

### MÓDULO 3 — Detector de Anomalias (`detector.py`)

#### Contexto

Enquanto o Motor de Regras analisa evento por evento isoladamente, o Detector de Anomalias olha para o **conjunto** de eventos e identifica **padrões de ataque** que só ficam visíveis quando você analisa múltiplos eventos juntos.

Um login falho isolado não é preocupante — pode ser alguém que errou a senha. Mas 50 logins falhos do mesmo IP em 30 segundos é claramente um ataque de brute force. Da mesma forma, um BLOCK no firewall é normal, mas se o mesmo IP tentou 15 portas diferentes em sequência, está fazendo um port scan.

Esse módulo precisa **agrupar**, **contar** e **correlacionar** eventos para encontrar esses padrões.

#### Requisitos Funcionais

1. **Detecção de Brute Force:** Identificar IPs com mais de N tentativas de login falhas
   - Contar FAILs por IP
   - Threshold configurável (padrão: 5)
   - Severidade escala com a quantidade: >5 MEDIA, >10 ALTA, >20 CRITICA
2. **Detecção de Port Scan:** Identificar IPs que tentaram acessar mais de N portas distintas
   - Contar portas únicas bloqueadas por IP (usar **set** para eliminar duplicatas)
   - Threshold configurável (padrão: 3 portas distintas)
3. **Detecção de IPs em Blacklist:** Cruzar todos os IPs dos eventos com uma blacklist
   - Usar operação de **interseção de sets** para encontrar IPs maliciosos conhecidos
4. **Resumo de ameaças:** Gerar um dicionário consolidado com todos os IPs suspeitos, motivos e severidade

#### Funções Esperadas

```python
def detectar_brute_force(eventos, threshold=5):
    """
    Conta tentativas FAIL por IP nos eventos de auth.
    Retorna dict: {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
    """

def detectar_port_scan(eventos, threshold=3):
    """
    Conta portas únicas (BLOCK) por IP nos eventos de firewall.
    Retorna dict: {ip: {"portas": set(...), "quantidade": N, "severidade": "..."}}
    """

def verificar_blacklist(eventos, blacklist):
    """
    Cruza IPs dos eventos com a blacklist usando operações de set.
    Retorna set de IPs maliciosos encontrados e dict com contagem por IP.
    """

def gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist):
    """
    Consolida todas as detecções em um resumo unificado.
    IPs que aparecem em múltiplas detecções têm severidade aumentada.
    Retorna lista de dicts ordenada por severidade.
    """
```

#### Dados de Teste

```python
# Blacklist para teste (definida no main.py ou em config)
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}
```

#### Cenários de Teste

| # | Cenário | Resultado Esperado |
|---|---------|-------------------|
| 1 | Processar auth.log | IP `185.220.101.1` detectado com 10 FAILs (ALTA), `91.240.118.172` com 5 FAILs (MEDIA), `45.33.32.156` com 3 FAILs (BAIXA) |
| 2 | Processar firewall.log | IP `185.220.101.1` detectado com 7 portas distintas (port scan ALTA), `91.240.118.172` com 3 portas (MEDIA) |
| 3 | Cruzar IPs com blacklist | Interseção retorna `{"185.220.101.1", "45.33.32.156", "91.240.118.172"}` — o IP `23.94.5.100` da blacklist **não** aparece nos logs |
| 4 | Resumo consolidado | `185.220.101.1` aparece em **3 detecções** (brute force + port scan + blacklist) = severidade CRITICA |
| 5 | Threshold de brute force alterado para 15 | Apenas `185.220.101.1` detectado (10 FAILs > 5 padrão, mas precisaria de novo threshold) |

#### Dicas de Implementação

- **Contar por IP:** Use um dicionário onde a chave é o IP e o valor é o contador. Itere pelos eventos com `for evento in eventos:` — **Aula 7, Seção 7.3** (dicionários) + **Aula 6** (loops)
- **Portas únicas:** Use um dicionário onde o valor é um **set** de portas: `portas_por_ip[ip].add(porta)`. Sets eliminam duplicatas automaticamente — **Aula 7, Seção 7.5** (sets)
- **Interseção com blacklist:** `ips_encontrados = ips_dos_eventos & blacklist` — **Aula 7, Seção 7.5** (operações de conjunto, exemplo com IPs da rede vs blacklist)
- **Ordenar por severidade:** Use `lista.sort(key=lambda x: x["pontuacao"], reverse=True)` — **Aula 10, Seção 10.4** (lambda com sort)
- **Classificação escalonada:** Use if-elif-else para mapear contagem → severidade — **Aula 4, Seção 4.3**
- **Múltiplos valores de retorno:** Funções podem retornar tuplas: `return brute_force, port_scan` — **Aula 7, Seção 7.2** (desempacotamento de tuplas) + **Aula 10, Seção 10.2**

---

### MÓDULO 4 — Servidor de Alertas em Tempo Real (`servidor_alertas.py` + `cliente_alertas.py`)

#### Contexto

Em um SOC real, os analistas não ficam olhando um terminal esperando o programa terminar de processar. Eles têm **consoles de monitoramento** que recebem alertas em tempo real — quando algo acontece, o alerta aparece instantaneamente na tela de todos os analistas de plantão.

Este módulo implementa essa funcionalidade usando sockets TCP. O **servidor** é o componente central do SIEM que processa os eventos e, quando gera um alerta, envia para todos os **clientes** (consoles) conectados via rede. Isso usa o mesmo modelo cliente-servidor do exercício de chat da **Aula 13**.

#### Requisitos Funcionais

1. **Servidor TCP** que aceita múltiplas conexões simultâneas (threading)
2. **Broadcast de alertas** — quando um alerta é gerado, envia para todos os clientes conectados
3. **Formatação do alerta** em texto legível com severidade, IP, regra e detalhes
4. **Comandos do cliente:**
   - `/status` — mostra quantos clientes conectados e alertas na sessão
   - `/historico` — recebe os últimos 10 alertas
   - `/sair` — desconecta do servidor
5. **Tratamento de desconexões** — remover clientes que cairam sem travar o servidor
6. **Log de conexões** — registrar no console do servidor quem conectou/desconectou

#### Funções Esperadas

```python
# servidor_alertas.py

def iniciar_servidor(host="0.0.0.0", porta=9999):
    """Inicia o servidor TCP e fica aguardando conexões."""

def tratar_cliente(conexao, endereco):
    """Gerencia comunicação com um cliente individual (roda em thread)."""

def broadcast_alerta(alerta):
    """Envia um alerta formatado para todos os clientes conectados."""

def formatar_alerta(alerta_dict):
    """
    Converte dict de alerta em string formatada para exibição.
    Formato: [TIMESTAMP] [SEVERIDADE] REGRA — IP — Descrição
    Exemplo: [08:15:01] [CRITICA] Brute Force — 185.220.101.1 — 10 tentativas em 30s
    """

# cliente_alertas.py

def conectar_servidor(host="127.0.0.1", porta=9999):
    """Conecta ao servidor e fica recebendo alertas."""

def receber_alertas(cliente):
    """Thread que recebe e exibe alertas do servidor."""
```

#### Cenário de Teste (executar em múltiplos terminais)

```
Terminal 1 — Servidor:
$ python servidor_alertas.py
=== Servidor de Alertas SecuraPy ===
Rodando em 0.0.0.0:9999
Aguardando conexões...

[08:30:01] Cliente conectado: 127.0.0.1:54321
[08:30:05] Cliente conectado: 127.0.0.1:54322
[08:30:10] Alerta enviado para 2 clientes: [CRITICA] Brute Force — 185.220.101.1

Terminal 2 — Cliente 1:
$ python cliente_alertas.py
Conectado ao SecuraPy SIEM (127.0.0.1:9999)
Comandos: /status, /historico, /sair

[08:30:10] [CRITICA] Brute Force — 185.220.101.1 — 10 tentativas de login falhas
[08:30:10] [ALTA] Port Scan — 185.220.101.1 — 7 portas escaneadas (22,23,445,3306,...)
[08:30:11] [ALTA] Path Traversal — 91.240.118.172 — GET /../../etc/passwd

>> /status
Clientes conectados: 2 | Alertas na sessão: 3

Terminal 3 — Cliente 2:
$ python cliente_alertas.py
(recebe os mesmos alertas que o Cliente 1)
```

#### Cenários de Teste

| # | Cenário | Resultado Esperado |
|---|---------|-------------------|
| 1 | Iniciar servidor e conectar 2 clientes | Servidor mostra 2 conexões, clientes recebem mensagem de boas-vindas |
| 2 | Servidor envia alerta | Ambos os clientes recebem o mesmo alerta formatado |
| 3 | Cliente 1 desconecta (/sair) | Servidor remove cliente, cliente 2 continua recebendo alertas |
| 4 | Cliente envia `/status` | Recebe contagem de clientes e alertas |
| 5 | Cliente envia `/historico` | Recebe os últimos 10 alertas da sessão |
| 6 | Servidor para (Ctrl+C) | Clientes recebem mensagem de desconexão |

#### Dicas de Implementação

- **Servidor TCP base:** O código da **Aula 13, Seção 13.2** tem o esqueleto completo de um servidor com `bind`, `listen`, `accept`
- **Threading:** Cada cliente roda em uma thread separada, exatamente como no chat da **Aula 13, Seção 13.3** — use `threading.Thread(target=tratar_cliente, args=(conexao, endereco))`
- **Broadcast:** Mesma lógica da função `broadcast()` do exercício de chat da **Aula 13** — itere pelo dicionário de clientes e envie para cada um, com `lock` para evitar concorrência
- **Dicionário de clientes:** Use `clientes = {}` com `{conexao: apelido}` — **Aula 7, Seção 7.3**
- **Lock para concorrência:** `lock = threading.Lock()` e `with lock:` antes de modificar o dicionário compartilhado — **Aula 13** (exercício de chat)
- **Tratamento de erros de rede:** Envolva `send()` e `recv()` em `try/except (ConnectionResetError, BrokenPipeError)` — **Aula 8, Seção 8.2**
- **Formatar alerta:** Use f-strings com alinhamento — **Aula 3, Seção 3.3**

---

### MÓDULO 5 — Enriquecimento de IPs (`enriquecimento.py`)

#### Contexto

Quando o SIEM detecta um IP suspeito, a primeira pergunta do analista é: "de onde vem esse IP?". Um IP da China tentando acessar SSH de um servidor brasileiro às 3h da manhã é muito mais preocupante do que um IP da rede interna.

Enriquecimento é o processo de adicionar **contexto** a um alerta consultando fontes externas de inteligência. Neste módulo, vocês vão consultar a API pública do **ipinfo.io** para obter geolocalização, organização (ISP) e outras informações de cada IP suspeito.

Além disso, o módulo deve classificar se o IP é **privado** (rede interna) ou **público** (internet), já que IPs privados não precisam ser consultados externamente.

#### Requisitos Funcionais

1. **Classificar IPs** em privados (10.x.x.x, 172.16-31.x.x, 192.168.x.x) e públicos
2. **Consultar API** `https://ipinfo.io/{ip}/json` para cada IP público suspeito
3. **Extrair informações:** cidade, região, país, organização, hostname
4. **Cache de consultas** — se o mesmo IP já foi consultado, não consultar novamente (usar dicionário como cache)
5. **Tratar erros:** timeout, API indisponível, IP inválido, limite de requisições (status 429)
6. **Retornar dados enriquecidos** como dicionário

#### Funções Esperadas

```python
def eh_ip_privado(ip):
    """
    Verifica se um IP é de rede privada (RFC 1918).
    Retorna True para 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    """

def consultar_ip(ip, cache):
    """
    Consulta ipinfo.io para obter dados do IP.
    Usa cache (dict) para evitar consultas repetidas.
    Retorna dict com: ip, cidade, regiao, pais, org, hostname
    """

def enriquecer_alertas(alertas, cache):
    """
    Recebe lista de alertas e adiciona informações de geolocalização.
    Pula IPs privados (marca como "Rede Interna").
    Retorna alertas enriquecidos.
    """

def exibir_enriquecimento(dados_ip):
    """Exibe as informações do IP de forma formatada."""
```

#### Cenários de Teste

| # | Cenário | Resultado Esperado |
|---|---------|-------------------|
| 1 | Consultar `8.8.8.8` | Retorna: Mountain View, California, US, Google LLC |
| 2 | Consultar `192.168.1.10` | Classificado como privado, **sem** consulta à API, retorna "Rede Interna" |
| 3 | Consultar mesmo IP duas vezes | Segunda consulta retorna do cache, sem chamada HTTP |
| 4 | Consultar IP inválido `999.999.999.999` | Tratamento de erro, retorna dados vazios/padrão |
| 5 | API indisponível (simule desconectando a internet) | Mensagem de erro, programa não trava |
| 6 | Enriquecer alertas com IPs mistos (privados e públicos) | Privados marcados como "Rede Interna", públicos com dados da API |

#### Dicas de Implementação

- **Requisições HTTP:** Use `requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)` — **Aula 14** (exemplo com `requests.get` e API do GitHub)
- **Parsear resposta JSON:** Use `resposta.json()` para converter a resposta em dicionário — **Aula 14** (seção sobre JSON)
- **Verificar status code:** `if resposta.status_code == 200:` — **Aula 14** (tabela de status codes)
- **Cache com dicionário:** `cache = {}` e `if ip in cache: return cache[ip]` — **Aula 7, Seção 7.3** (busca O(1) em dicionário)
- **Classificar IP privado:** Extraia o primeiro octeto com `ip.split(".")` e verifique com condicionais — **Aula 10, Exercício 2** (filtrar IPs válidos/privados/públicos)
- **Tratar erros de rede:** Use múltiplos `except` para `ConnectionError`, `Timeout`, `HTTPError` — **Aula 14** (função `requisicao_segura`)
- **f-strings para URL:** `url = f"https://ipinfo.io/{ip}/json"` — **Aula 3, Seção 3.3**

---

### MÓDULO 6 — Dashboard CLI e Relatórios (`relatorios.py`)

#### Contexto

De nada adianta o SIEM detectar ameaças se o analista não consegue visualizar e consultar os resultados. O Dashboard é a interface do sistema com o operador. Ele deve apresentar os dados de forma clara, permitir filtros e buscas, e gerar relatórios que possam ser salvos e compartilhados.

Este módulo também é o **menu principal** do programa (`main.py`), integrando todos os outros módulos em uma experiência unificada.

#### Requisitos Funcionais

1. **Menu principal interativo** com opções numeradas e loop contínuo
2. **Resumo geral:** Total de eventos por fonte, total de alertas por severidade
3. **Filtrar eventos** por: fonte (auth/firewall/web), tipo (FAIL/BLOCK), IP específico
4. **Buscar IP:** Exibir todos os eventos de um IP + dados enriquecidos + alertas relacionados
5. **Top 10 IPs** mais ativos (por número de eventos) com indicação de ameaça
6. **Relatório completo** exportado em JSON com todos os dados da análise
7. **Relatório formatado** exibido no terminal com colunas alinhadas
8. **Validação de entrada** — o menu não pode travar se o usuário digitar algo inválido

#### Funções Esperadas

```python
def exibir_menu():
    """Exibe o menu principal e retorna a opção escolhida (validada)."""

def resumo_geral(eventos, alertas):
    """Exibe contadores gerais: eventos por fonte, alertas por severidade."""

def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    """Retorna eventos filtrados pelos critérios. None = sem filtro."""

def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    """Exibe relatório completo de um IP: eventos, alertas, geolocalização."""

def top_ips(eventos, n=10):
    """Retorna os N IPs com mais eventos, com contagem e classificação."""

def exportar_relatorio_json(dados, caminho):
    """Salva relatório completo em JSON formatado."""

def exibir_tabela(dados, colunas):
    """Exibe uma lista de dicts como tabela formatada no terminal."""
```

#### Formato do Menu Principal (`main.py`)

```
╔══════════════════════════════════════════╗
║         SecuraPy SIEM — Menu             ║
╠══════════════════════════════════════════╣
║  1. Carregar e processar logs            ║
║  2. Resumo geral                         ║
║  3. Filtrar eventos                      ║
║  4. Buscar IP                            ║
║  5. Top 10 IPs suspeitos                 ║
║  6. Ver alertas por severidade           ║
║  7. Enriquecer IPs suspeitos             ║
║  8. Exportar relatório JSON              ║
║  9. Iniciar servidor de alertas          ║
║  0. Sair                                 ║
╚══════════════════════════════════════════╝
```

#### Cenários de Teste

| # | Cenário | Resultado Esperado |
|---|---------|-------------------|
| 1 | Opção 1 — Carregar logs | Exibe: "23 eventos de auth, 17 de firewall, 18 de web. Total: 58 eventos" |
| 2 | Opção 3 — Filtrar por fonte `auth` e tipo `FAIL` | Exibe apenas os eventos de autenticação com falha |
| 3 | Opção 4 — Buscar IP `185.220.101.1` | Exibe todos os eventos desse IP (das 3 fontes), alertas e info geográfica |
| 4 | Opção 5 — Top 10 | Lista ordenada por quantidade, com indicadores visuais de ameaça |
| 5 | Opção 8 — Exportar JSON | Arquivo salvo em `saida/relatorio_YYYYMMDD_HHMMSS.json` com todos os dados |
| 6 | Digitar "abc" no menu | Mensagem "Opção inválida", menu reaparece |
| 7 | Opção 4 sem ter carregado logs (opção 1) | Mensagem "Carregue os logs primeiro (opção 1)" |

#### Dicas de Implementação

- **Menu com while True:** Loop infinito com `input()` e if-elif-else — **Aula 6, Seção 6.4** (while) + **Aula 4**
- **Validação de input:** Envolva `int(input())` em try/except ValueError — **Aula 8, Seção 8.2**
- **Contar eventos por fonte:** Use dicionário como contador: `contadores[evento["fonte"]] += 1` — **Aula 7, Seção 7.3** (veja exercício 2 da Aula 7, contagem de requisições por IP)
- **Filtrar com list comprehension:** `[e for e in eventos if e["fonte"] == fonte]` — **Aula 7, Seção 7.1**
- **Exportar JSON:** Use `json.dump(dados, arquivo, indent=2, ensure_ascii=False)` — **Aula 14** (seção sobre JSON, salvando em arquivo)
- **Gerar nome do arquivo com timestamp:** Use `datetime.now().strftime("relatorio_%Y%m%d_%H%M%S.json")` — **Aula 11** (módulo datetime)
- **Criar pasta de saída:** Use `os.makedirs("saida", exist_ok=True)` — **Aula 11, Seção 11.2** (módulo os)
- **Tabela formatada:** Use f-strings com largura fixa: `f"{'IP':<20}{'Eventos':>8}{'Severidade':<10}"` — **Aula 3, Seção 3.3**

---

## 4. Integração dos Módulos (`main.py`)

O `main.py` é o ponto de entrada que importa e orquestra todos os módulos:

```python
# main.py — Estrutura esperada (implementem o conteúdo)

from coletor import carregar_todos_os_logs
from regras import carregar_regras, aplicar_regras
from detector import detectar_brute_force, detectar_port_scan, verificar_blacklist, gerar_resumo_ameacas
from enriquecimento import enriquecer_alertas
from relatorios import exibir_menu, resumo_geral, filtrar_eventos, buscar_ip, top_ips, exportar_relatorio_json

# Configurações
PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}

def main():
    eventos = []
    alertas = []
    cache_enriquecimento = {}

    while True:
        opcao = exibir_menu()

        if opcao == 1:
            # Carregar e processar logs
            # 1. carregar_todos_os_logs()
            # 2. carregar_regras()
            # 3. aplicar_regras()
            # 4. detectar_brute_force(), detectar_port_scan(), verificar_blacklist()
            # 5. gerar_resumo_ameacas()
            pass

        elif opcao == 2:
            # Resumo geral
            pass

        # ... demais opções ...

        elif opcao == 0:
            print("Encerrando SecuraPy. Até logo!")
            break

if __name__ == "__main__":
    main()
```

> **Referência:** A organização com `if __name__ == "__main__":` e imports de módulos próprios está na **Aula 11, Seção 11.5**.

---

## 5. Entregáveis

| # | Entregável | Descrição |
|---|-----------|-----------|
| 1 | **Código-fonte** | Pasta `securaPy/` completa com todos os `.py`, arquivos de log, config e saída |
| 2 | **README.md** | Documentação com: nome dos integrantes, descrição do projeto, como executar, dependências (`pip install requests`), divisão de tarefas por integrante |
| 3 | **Apresentação** | Demonstração em video do sistema funcionando (10-15 minutos, me enviar pelo teams): carregar logs, mostrar alertas, filtrar, buscar IP, demonstrar servidor de alertas com 2 clientes |
| 4 | **Relatório de exemplo** | Um arquivo JSON de relatório gerado pelo sistema com os dados de teste |

---

## 6. Critérios de Avaliação

A nota total do trabalho é **10,0 pontos**, distribuídos da seguinte forma:

---

### 6.1 Funcionalidade (5,0 pontos)

Cada módulo vale proporcionalmente ao esforço e complexidade:

| Módulo | Pontuação | Critério |
|--------|-----------|----------|
| **Módulo 1 — Coletor** | **0,8** | Lê os 3 arquivos, parseia corretamente, normaliza em dicts padronizados |
| **Módulo 2 — Regras** | **0,8** | Carrega JSON, aplica pelo menos 5 regras, classifica severidade |
| **Módulo 3 — Detector** | **1,0** | Detecta brute force, port scan e blacklist corretamente; resumo consolidado funcional |
| **Módulo 4 — Servidor** | **1,0** | Servidor TCP aceita múltiplos clientes, broadcast funciona, comandos implementados |
| **Módulo 5 — Enriquecimento** | **0,7** | Consulta API, distingue IP privado/público, cache funcional |
| **Módulo 6 — Dashboard/Relatórios** | **0,7** | Menu funcional, filtros, busca por IP, exportação JSON |

**Detalhamento por módulo:**

- **Nota máxima:** Todos os requisitos implementados e funcionando
- **Nota parcial (50%-80%):** Funcionalidade principal implementada, alguns requisitos faltando
- **Nota mínima (30%-50%):** Estrutura presente mas com bugs significativos ou requisitos essenciais faltando
- **Zero:** Módulo não implementado ou não funcional

---

### 6.2 Tratamento de Erros (1,0 ponto)

| Critério | Pontuação |
|----------|-----------|
| Arquivo de log inexistente não trava o programa | 0,15 |
| Linha de log malformada é ignorada com aviso | 0,15 |
| JSON de configuração inválido é tratado | 0,10 |
| Input inválido no menu não trava o programa | 0,15 |
| Erros de rede (API, socket) são tratados | 0,15 |
| Desconexão de cliente não derruba o servidor | 0,15 |
| Uso correto de try/except com exceções específicas (não usar `except:` genérico sem justificativa) | 0,15 |

---

### 6.3 Qualidade do Código (1,5 pontos)

| Critério | Pontuação |
|----------|-----------|
| **Modularização:** Código separado em arquivos conforme a arquitetura; funções com responsabilidade única | 0,40 |
| **Nomes significativos:** Variáveis, funções e arquivos com nomes claros e em português ou inglês consistente | 0,20 |
| **Estruturas de dados adequadas:** Uso correto de listas, dicts, sets e tuplas conforme o problema | 0,30 |
| **Funções bem definidas:** Parâmetros claros, retornos documentados, sem funções com mais de 50 linhas | 0,30 |
| **Sem código duplicado:** Funcionalidade compartilhada extraída em funções reutilizáveis | 0,30 |

---

### 6.4 Documentação e Apresentação (1,5 pontos)

| Critério | Pontuação |
|----------|-----------|
| **README.md completo:** Integrantes, descrição, instruções de execução, dependências | 0,30 |
| **Divisão de tarefas:** Documentação clara de quem fez o quê | 0,20 |
| **Apresentação em video:** Demonstração fluida do sistema funcionando com os dados de teste | 1,00 |
 
**Observação importante:** cada integrante deve apresentar a parte em contribuiu no projeto e ao final da apresentação um integrante deve fazer um teste ponta a ponta com todas as funcionalidades do sistema

---

### 6.5 Bônus (até +1,0 ponto extra)

Funcionalidades opcionais que demonstram domínio acima do esperado:

| Bônus | Pontuação |
|-------|-----------|
| **Correlação temporal:** Detectar brute force considerando janela de tempo (ex: >5 FAILs em 60 segundos, não apenas contagem total) | +0,30 |
| **Hash de integridade:** Gerar hash SHA-256 dos arquivos de log e verificar se foram alterados entre execuções (usando hashlib) | +0,20 |
| **Geração automática de logs:** Script que gera logs aleatórios simulando tráfego normal e ataques para testar o sistema | +0,20 |
| **Regras customizadas:** Permitir ao operador criar novas regras pelo menu (adicionando ao JSON) sem editar código | +0,30 |

---

### Resumo da Pontuação

| Categoria | Pontuação |
|-----------|-----------|
| Funcionalidade | 5,0 |
| Tratamento de Erros | 1,0 |
| Qualidade do Código | 1,5 |
| Documentação e Apresentação | 1,5 |
| **Total** | **10,0** |
| Bônus (extra) | até +1,0 |

---

## 7. Sugestão de Divisão de Trabalho

### Equipe de 4 pessoas

| Integrante | Responsabilidade | Módulos |
|-----------|-----------------|---------|
| **Pessoa A** | Coleta e parsing de dados | Módulo 1 (coletor.py) + arquivos de log de teste |
| **Pessoa B** | Inteligência e detecção | Módulo 2 (regras.py) + Módulo 3 (detector.py) + regras.json |
| **Pessoa C** | Comunicação em rede | Módulo 4 (servidor_alertas.py + cliente_alertas.py) |
| **Pessoa D** | Interface e integração | Módulo 5 (enriquecimento.py) + Módulo 6 (relatorios.py) + main.py |

### Equipe de 3 pessoas

| Integrante | Responsabilidade | Módulos |
|-----------|-----------------|---------|
| **Pessoa A** | Coleta e detecção | Módulo 1 (coletor.py) + Módulo 3 (detector.py) |
| **Pessoa B** | Regras e rede | Módulo 2 (regras.py) + Módulo 4 (servidor + cliente) |
| **Pessoa C** | Enriquecimento e interface | Módulo 5 (enriquecimento.py) + Módulo 6 (relatorios.py) + main.py |

---

## 8. Dicas Gerais

1. **Comecem pelo Módulo 1** — todos os outros dependem de ter eventos carregados
2. **Testem cada módulo isoladamente** antes de integrar. Cada arquivo `.py` pode ter um bloco `if __name__ == "__main__":` com testes próprios
3. **Usem os dados de teste fornecidos** — eles foram desenhados para disparar todas as regras e detecções
4. **Combinem as interfaces cedo** — definam juntos o formato dos dicionários (evento, alerta) para que os módulos se encaixem
5. **Não deixem o servidor de alertas para o final** — é o módulo mais complexo e precisa de tempo para debugar
6. **Git é seu amigo** — se possível, usem controle de versão para trabalhar em paralelo sem conflitos

---

**Bom trabalho! Lembrem-se: em segurança, cada detalhe importa.**
