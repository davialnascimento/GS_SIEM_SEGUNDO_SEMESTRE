# SecuraPy SIEM — Trabalho Final

## Como usar este projeto

O SecuraPy é o núcleo SIEM implementado em Python e integrado à plataforma web VioTrace.

O sistema processa logs de autenticação, firewall e acesso web, aplica regras configuráveis, identifica padrões de brute force, port scan e blacklist, permite consultas e gera relatórios JSON.

Também possui um servidor TCP que transmite alertas já processados para múltiplos clientes conectados.

### Validação com testes automatizados

A implementação do núcleo foi validada com 197 testes automatizados aprovados. Esses testes não representam uma auditoria de segurança completa da plataforma web.

#### Instalando as dependências

```bash
# Na pasta securaPy/
pip install pytest requests
```

#### Rodando todos os testes

```bash
# Na pasta securaPy/
python -m pytest testes/ -v
```

#### Rodando testes de um módulo específico

```bash
# Testar apenas o coletor
python -m pytest testes/test_coletor.py -v

# Testar apenas as regras
python -m pytest testes/test_regras.py -v

# Testar apenas o detector
python -m pytest testes/test_detector.py -v

# Testar apenas o enriquecimento
python -m pytest testes/test_enriquecimento.py -v

# Testar apenas o servidor de alertas
python -m pytest testes/test_servidor.py -v

# Testar apenas os relatórios
python -m pytest testes/test_relatorios.py -v

# Testar apenas a integração (ponta a ponta)
python -m pytest testes/test_integracao.py -v
```

#### Rodando um teste específico

```bash
# Rodar apenas um teste por nome
python -m pytest testes/test_coletor.py::TestParsearLinhaAuth::test_linha_fail_retorna_dict -v
```

#### Vendo quantos testes passam vs falham

```bash
python -m pytest testes/ --tb=no -q
```

Resultado esperado da versão implementada:
```
197 passed, 0 failed
```

### Módulos implementados

O núcleo SecuraPy é organizado nos seguintes módulos:

1. **`coletor.py`** — base de tudo (rode `test_coletor.py`)
2. **`regras.py`** — precisa do coletor (rode `test_regras.py`)
3. **`detector.py`** — precisa do coletor (rode `test_detector.py`)
4. **`enriquecimento.py`** — independente (rode `test_enriquecimento.py`)
5. **`relatorios.py`** — precisa de todos (rode `test_relatorios.py`)
6. **`servidor_alertas.py` + `cliente_alertas.py`** — independente (rode `test_servidor.py`)
7. **`main.py`** — integra tudo (rode `test_integracao.py`)

### Estrutura do projeto

```
securaPy/
├── main.py                  # Ponto de entrada — menu principal
├── coletor.py               # Módulo 1 — Leitura e parsing de logs
├── regras.py                # Módulo 2 — Motor de regras de detecção
├── detector.py              # Módulo 3 — Detecção de anomalias
├── servidor_alertas.py      # Módulo 4a — Servidor TCP de alertas
├── cliente_alertas.py       # Módulo 4b — Cliente TCP de alertas
├── enriquecimento.py        # Módulo 5 — Consulta API de geolocalização
├── relatorios.py            # Módulo 6 — Dashboard CLI e relatórios
├── logs/                    # Arquivos de log para teste
│   ├── auth.log
│   ├── firewall.log
│   └── web_access.log
├── config/
│   └── regras.json          # Configuração das regras de detecção
├── saida/                   # Relatórios gerados (pasta de saída)
├── testes/                  # Testes automatizados
│   ├── conftest.py          # Fixtures compartilhadas
│   ├── test_coletor.py      # Testes do módulo 1
│   ├── test_regras.py       # Testes do módulo 2
│   ├── test_detector.py     # Testes do módulo 3
│   ├── test_servidor.py     # Testes do módulo 4
│   ├── test_enriquecimento.py  # Testes do módulo 5
│   ├── test_relatorios.py   # Testes do módulo 6
│   └── test_integracao.py   # Testes ponta a ponta
└── README.md                # Este arquivo
```

### Mapa de testes por módulo

| Módulo | Arquivo de teste | Testes | O que valida |
|--------|-----------------|--------|-------------|
| coletor.py | test_coletor.py | 47 | Parsing dos 3 formatos de log, normalização, erros de arquivo |
| regras.py | test_regras.py | 37 | Carregamento JSON, classificação severidade, avaliação de cada regra |
| detector.py | test_detector.py | 38 | Brute force, port scan, blacklist, resumo consolidado |
| enriquecimento.py | test_enriquecimento.py | 26 | IP privado/público, cache, mock de API, tratamento de erros |
| servidor_alertas.py | test_servidor.py | 7 | Formatação de alertas, conexão TCP, broadcast |
| relatorios.py | test_relatorios.py | 30 | Filtros, top IPs, exportação JSON, menu |
| integração | test_integracao.py | 12 | Fluxo completo ponta a ponta |
| | | **197** | **Total** |

---


# SecuraPy SIEM — [CodeShield]




## Integrantes

| Nome | RM | Responsabilidade |
|------|-----|-----------------|
| [Amanda Souza Bezerra] |   [RM573911]    | [Rede, Servidor e Cliente] |

| [Caique dos Santos Rodrigues] | [RM570577] | [Enriquecimento e interface] |

| [Davi almeida Nascimento] | [RM569447] | [.....] |

| [Maick Rosario Yamassaki] | [RM569664] | Coleta e parsing de dados |





## Descrição

O SecuraPy detecta ameaças em logs de autenticação, firewall e acesso web de forma automática, substituindo a análise manual que atrasa a resposta a incidentes. A detecção funciona em duas camadas: o regras.py avalia eventos individualmente contra condições configuradas em JSON (força bruta por usuário, portas críticas, XSS, path traversal), enquanto o detector.py correlaciona eventos em conjunto para identificar padrões como brute force e port scan, cruzando ainda os IPs encontrados com uma blacklist.

O fluxo começa no coletor.py, que normaliza os logs das três fontes num formato único. Os eventos passam pelo motor de regras e pelo detector, têm os IPs enriquecidos com geolocalização via enriquecimento.py e chegam ao relatorios.py, onde o operador filtra, busca e exporta resultados. Os alertas são transmitidos em tempo real via TCP pelo servidor_alertas.py para todos os clientes conectados, e tudo é orquestrado pelo menu interativo do main.py.




## Resultado dos testes


testes/test_servidor.py::TestServidorIntegracao::test_broadcast_envia_para_multiplos PASSED [100%]

============================= 197 passed in 1.34s ==============================



## Divisão de tarefas


### [Maick Rosario Yamassaki — Pessoa A]
- **Módulos:** [1 e 3]

- **O que fez:** [implementou a leitura e normalização dos logs das três fontes (auth, firewall, web) e a detecção de anomalias por correlação de eventos. Desenvolveu as funções de brute force, port scan e cruzamento com blacklist.]

- **Dificuldades:** [implementar o tratamento de erros e a resiliência do coletor.
Garantir que o sistema não travasse ao encontrar arquivos inexistentes ou linhas malformadas  e, ao mesmo tempo, conseguir extrair dados úteis dessas linhas "sujas" sem interromper o processamento
Exigiu um equilíbrio cuidadoso entre o uso de ⁠try/except⁠ e a lógica de validação. Conciliar a robustez do tratamento de exceções com a necessidade de relatar exatamente onde e por que um erro ocorria foi uma dificuldade para manter o código funcional.]



### [Amanda Souza Bezerra — Pessoa B]

- **Módulos:** [2 e 4]

- **O que fez:** [Amanda desenvolveu o motor de regras que avalia cada evento contra condições configuradas em JSON, gerando alertas com severidade classificada. Implementou também o servidor TCP de alertas e o cliente que recebe as notificações em tempo real.]

- **Dificuldades:** [Motor de Regras
A dificuldade foi que cada regra precisava “enxergar” uma coisa diferente dentro do log. Uma precisava encontrar o usuário, outra a porta, outra um padrão na URL. A solução foi percorrer cada parte da linha procurando o campo certo para cada situação.
Servidor com múltiplos clientes
O problema foi que vários clientes conectando ao mesmo tempo podiam causar conflito na lista de conexões. A solução foi usar um “cadeado” no código (Lock) que impede duas operações de acontecerem ao mesmo tempo no mesmo lugar.]



### [Caique Dos Santos Rodrigues — Pessoa C]
- **Módulos:** [5 e 6]

- **O que fez:** [construiu o módulo de enriquecimento de IPs com consulta à API do ipinfo.io e cache local, além do dashboard CLI com filtros, busca e exportação de relatórios. Integrou todos os módulos no main.py, orquestrando o fluxo completo do sistema.]

- **Dificuldades:** [O principal desafio foi a integração com uma API externa na etapa de enriquecimento dos dados. Em alguns momentos, a API podia retornar erros ou demorar para responder, o que afetava o funcionamento do sistema. Para resolver isso, implementei validações e tratamento de exceções. Dessa forma, a aplicação consegue lidar com falhas sem interromper a execução. Isso tornou o processo mais confiável e estável..]



### [Davi — Pessoa D]
- **Módulos:** [...]
- **O que fez:** [...]
- **Dificuldades:** [...]




## Demonstração em vídeo

[https://youtu.be/vMkXqQ5vU6w]
