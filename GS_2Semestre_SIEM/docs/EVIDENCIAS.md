# Evidências de validação — VioTrace

Este documento organiza capturas para apresentação acadêmica. **Não inclua senhas, tokens de sessão ou códigos de convite ativos nos prints.**

## Resultado já verificado durante o desenvolvimento

- **Núcleo Python:** `197 passed in 1.20s` (08/11/2026), execução de `py -m pytest testes/ -v` em `securaPy/`.
- **Cenário de laboratório:** 58 eventos processados, 31 alertas de regras e 3 IPs correlacionados.
- **Logs:** 23 eventos de autenticação; filtro `FAIL`: 19 eventos.
- **Regras:** desativação da R005 reduziu alertas de 31 para 27; reativação restaurou 31.
- **Investigação por IP:** `185.220.101.1` apresentou 25 eventos e 15 alertas associados.
- **TCP:** um cliente conectado em `127.0.0.1:9999` recebeu 31 alertas processados.
- **Controle de acesso:** analista autenticado recebeu **HTTP 403** ao acessar rota administrativa.
- **Usuários:** cadastro por convite, suspensão, bloqueio de login e reativação foram demonstrados.
- **Assistente IA:** Ollama `llama3.2:3b` respondeu com contexto do relatório, após correção do envio de correlações.

## Capturas recomendadas para anexar à entrega

1. Visão geral UX 2.0 com data do último processamento e indicadores.
2. Filtros de eventos (fonte `auth` e tipo `FAIL`).
3. Aba de correlações (brute force, port scan e blacklist).
4. Investigação de IP, com eventos e alertas relacionados.
5. Regras R001–R005 ativas, sem modificar regras antes de apresentar.
6. Status TCP e janela do cliente recebendo alertas.
7. Assistente IA e resposta fundamentada, evitando alegações não verificadas.
8. Administração com dois perfis; **não mostrar códigos de convite**.
9. Terminal com `197 passed` no Pytest.
10. Teste HTTP 403 de um analista em rota administrativa, sem mostrar tokens.

## Limites dos resultados

O conjunto de testes Pytest valida o **SecuraPy original**. As rotas FastAPI, integração React, permissões e LLM foram submetidas a verificações manuais e testes locais adicionais. O resultado não deve ser apresentado como auditoria de produção, *pentest* completo ou monitoramento contínuo de ativos reais.
