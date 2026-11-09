# VioTrace — Complemento dos módulos E e G (Coding for Security)

Escopo: corrigir SOMENTE E/G no projeto existente. NÃO implementa B/Mongo,
C/ML, D/Flask completo, F/Docker, nem substitui o projeto do grupo.

Arquivos criados:
- backend_ia/modulo_e.py: auditoria HTTP e cabeçalhos em toda resposta FastAPI;
  rota de demonstração XSS, isolada do relatório do SIEM, com escape HTML.
- backend_ia/assistente.py: classifica evento individual em NORMAL, SUSPEITO,
  CRÍTICO; Ollama local (temperature 0.1), saída JSON com validação,
  tratamento de prompt injection, redaction e fallback por regras.
- scripts/testar_modulos_eg.py: E1, E2, E3, E4, G1, G2, G3, G4 e 2 extras.
- backend_ia/app.py: novas rotas acopladas, sem modificar rota do chat de IP.
- frontend/vite.config.js: headers do Vite em dev e preview.

ATENÇÃO: a rubrica pede Flask + Jinja2; o VioTrace usa FastAPI + React.
Eles exercem papéis similares, mas não são a mesma tecnologia. Se a entrega
precisa ser Flask/Jinja2 literalmente, a adaptação depende do grupo/professor.

Instalação conservadora:
  cd C:\Users\caiqu\GS_1Semestre
  git switch main
  git switch -c feat/modulos-e-g-seguranca
  py "C:\Users\caiqu\Downloads\VioTrace_Modulos_E_G\instalar_modulos_eg.py"
  py .\scripts\testar_modulos_eg.py

Você pode extrair o ZIP em outro lugar e usar o caminho completo do instalador.
Rodar da raiz GS_1Semestre; não executar na pasta VioTrace_Projeto_Final.

Verificação depois de reiniciar Vite e FastAPI:
  GET http://127.0.0.1:8000/api/saude -> headers nosniff, DENY e CSP.
  GET http://127.0.0.1:5173/ -> headers (via Vite).
  backend_ia/dados/auditoria_acesso.log -> linhas JSON de requisições
  (método, rota SEM query string, status, tempo; nenhum token/senha).

Nova rota POST /api/classificar-evento (requer Bearer token já existente):
  {"evento":"GET /../../etc/passwd status=400", "modo":"mock"}
  -> classificacao CRÍTICO e origem fallback
  {"evento":"GET /index.html status=200", "modo":"mock"}
  -> NORMAL
  Em "auto" consulta Ollama se disponível, cai em fallback caso falhe.

Teste XSS (rota protegida por token, não altera os dados do SIEM):
  POST /api/modulo-e/alertas
  {"descricao":"<script>alert(1)</script>","severidade":"ALTA"}
  GET /api/modulo-e/alertas/html
  -> &lt;script&gt;alert(1)&lt;/script&gt;, nunca tag executável.

Limitações honestas:
- A rota de laboratório de alertas mantém apenas os últimos 30 em memória.
- O modo mock é baseado em indicadores conhecidos, não ML nem detecção ampla.
- A CSP do Vite em desenvolvimento permite script inline para React Refresh;
  para implantação real, usar build com CSP rigorosa na hospedagem final.
- Não foi feito pentest; os testes automatizados são funcionais e de regressão.
- O chat de investigação de IP original continua dependendo do Ollama;
  o fallback G3 é implementado na NOVA classificação de eventos individuais.

Depois dos testes, faça git add EXPLÍCITO (não git add .), revise diff,
e só então comite e proponha PR. Não comite dados privados nem evidências.
