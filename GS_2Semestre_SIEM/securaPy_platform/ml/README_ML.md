# Módulo C — Machine Learning (priorização de alertas)

## Como executar (da raiz do projeto)
```
pip install scikit-learn numpy joblib pytest
python -m ml.treinar        # C1: treina, imprime precisão/recall/F1, gera modelo.pkl + hash
python -m ml.classificar    # C2, C3, C4: demonstração
pytest ml/test_ml.py -v     # testes automatizados (bônus)
```

## Arquivos
| Arquivo | Função |
|---|---|
| `features.py` | Extrai 4 features por IP (n_fails, n_portas_distintas, na_blacklist, n_web_erros) |
| `treinar.py` | Dataset sintético + Pipeline (StandardScaler + RandomForest) + validação cruzada |
| `integridade.py` | SHA-256 do `modelo.pkl` (hashlib, leitura em blocos) |
| `classificar.py` | Verifica o hash, carrega o modelo e devolve score/nível/rótulo por IP |
| `anomalias.py` | Bônus: Isolation Forest treinado só com tráfego normal |
| `test_ml.py` | Testes pytest para C1–C4 e bônus |

## Uso pelos outros módulos
```python
from ml.classificar import pontuar, pontuar_eventos
pontuar(ameacas)          # {ip: {"score": 0.94, "nivel": "ALTO", "rotulo": "ataque"}}, ordenado
pontuar_eventos(eventos)  # mesmo resultado, a partir da lista de eventos do núcleo
```
Se o modelo estiver adulterado ou sem hash, levanta `IntegridadeError`
(a API deve capturar e responder sem vazar detalhes internos).

## Decisões de projeto
- **Dados sintéticos:** os logs de teste têm ~6 IPs, insuficiente para treinar e
  validar. O dataset é gerado com perfis (normal, normal barulhento, brute force,
  port scan, scanner web, combinado, discreto) que se sobrepõem, mais ~3% de ruído
  de rótulo, para o modelo aprender padrões e não decorar um limiar. Os IPs reais
  dos logs são usados apenas como teste de sanidade (C2/C3).
- **Pipeline:** o scaler fica dentro do Pipeline para que a padronização seja
  aprendida só com o treino em cada fold (sem vazamento de dados) e aplicada
  igual na classificação.
- **Métricas:** precisão, recall e F1 (não só acurácia), pois ataques são a
  classe minoritária; `class_weight="balanced"` compensa o desbalanceamento.
- **Integridade (OWASP A08):** `joblib.load` executa código de um .pkl; por isso
  o SHA-256 é conferido antes de carregar. Limitação: o hash fica ao lado do
  arquivo; em produção ele deveria ficar em local separado/assinado.
- **Níveis:** score >= 0,70 ALTO; >= 0,40 MEDIO; senão BAIXO. Rótulo "ataque" se >= 0,50.

## Ajuste necessário na integração
`BLACKLIST_PADRAO` em `features.py` deve ser igual à blacklist do núcleo (Módulo A).
