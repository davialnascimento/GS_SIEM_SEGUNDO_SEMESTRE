"""Treino do classificador de ataques (Módulo C — C1).

Uso (a partir da raiz do projeto):
    python -m ml.treinar

O que faz:
  1. Gera um dataset SINTÉTICO de IPs (os logs de teste têm só ~6 IPs, pouco
     para treinar/validar um modelo). Veja gerar_dataset_sintetico().
  2. Monta um Pipeline (StandardScaler + RandomForest).
  3. Avalia com validação cruzada estratificada (precisão, recall, F1) e com
     um conjunto de teste separado (classification_report).
  4. Treina o modelo final, salva com joblib e registra o SHA-256.
"""
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURES
from ml.integridade import MODELO_PATH, METRICAS_PATH, registrar_hash

SEED = 42


def gerar_dataset_sintetico(n=800, seed=SEED):
    """Gera n 'IPs' com as 4 features e o rótulo (0=normal, 1=ataque).

    O rótulo vem do PERFIL do IP (quem ele é), e NÃO de uma regra exata sobre
    as features. Os perfis se sobrepõem de propósito (ex.: um admin que errou
    a senha várias vezes é normal; um atacante discreto faz poucas tentativas),
    para o modelo aprender padrões em vez de decorar um limiar.
    Colunas: [n_fails, n_portas_distintas, na_blacklist, n_web_erros]
    """
    rng = np.random.default_rng(seed)
    X, y = [], []

    def add(fails, portas, bl, web, rotulo):
        X.append([fails, portas, bl, web])
        y.append(rotulo)

    for _ in range(n):
        p = rng.random()
        if p < 0.60:        # tráfego normal
            add(rng.poisson(1), rng.poisson(1.5), rng.random() < 0.02, rng.poisson(1.5), 0)
        elif p < 0.70:      # normal "barulhento" (admin errando senha, app com 404)
            add(rng.poisson(4), rng.poisson(2), 0, rng.poisson(5), 0)
        elif p < 0.80:      # brute force
            add(rng.poisson(10) + 3, rng.poisson(1.5), rng.random() < 0.6, rng.poisson(1), 1)
        elif p < 0.88:      # port scan
            add(rng.poisson(1), 5 + rng.poisson(4), rng.random() < 0.6, rng.poisson(1), 1)
        elif p < 0.94:      # scanner web / path traversal
            add(rng.poisson(1), rng.poisson(2), rng.random() < 0.5, 6 + rng.poisson(6), 1)
        elif p < 0.98:      # ataque combinado
            add(rng.poisson(8) + 2, 4 + rng.poisson(3), rng.random() < 0.8, rng.poisson(4), 1)
        else:               # atacante discreto (baixo volume, mas na blacklist)
            add(rng.poisson(3), rng.poisson(2), 1, rng.poisson(3), 1)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    # ~3% de ruído de rótulo (o mundo real nunca é perfeito)
    flip = rng.random(len(y)) < 0.03
    y[flip] = 1 - y[flip]
    return X, y


def criar_pipeline():
    """Scaler + modelo no MESMO Pipeline, para que a padronização aprendida no
    treino seja aplicada de forma idêntica na classificação (e não vaze dados
    do teste durante a validação cruzada)."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("modelo", RandomForestClassifier(
            n_estimators=200, class_weight="balanced", random_state=SEED)),
    ])


def treinar_e_avaliar(n=800, salvar=True, verbose=True):
    """Executa o fluxo completo e devolve um dict com as métricas."""
    X, y = gerar_dataset_sintetico(n=n)
    linhas = []

    def log(txt=""):
        linhas.append(txt)
        if verbose:
            print(txt)

    log("=" * 60)
    log("RELATÓRIO DE TREINO — SecuraPy ML (dados sintéticos)")
    log("=" * 60)
    log(f"Amostras: {len(y)} | ataques: {int(y.sum())} | normais: {int((1 - y).sum())}")
    log(f"Features: {FEATURES}")

    # --- Validação cruzada (5 folds estratificados) ---
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    res = cross_validate(criar_pipeline(), X, y, cv=cv,
                         scoring=["accuracy", "precision", "recall", "f1"])
    metricas = {}
    log("\n--- Validação cruzada (5 folds) ---")
    for nome in ("accuracy", "precision", "recall", "f1"):
        valores = res[f"test_{nome}"]
        metricas[nome] = float(valores.mean())
        log(f"{nome:<10}: {valores.mean():.3f} (+/- {valores.std():.3f})")

    # --- Conjunto de teste separado ---
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=SEED)
    pipe = criar_pipeline().fit(X_tr, y_tr)
    previsto = pipe.predict(X_te)
    log("\n--- Conjunto de teste (25%) ---")
    log(f"Matriz de confusão [[VN FP] [FN VP]]:\n{confusion_matrix(y_te, previsto)}")
    log(classification_report(y_te, previsto, target_names=["normal", "ataque"]))

    # --- Importância das features ---
    imp = pipe.named_steps["modelo"].feature_importances_
    log("--- Importância das features ---")
    for nome, v in sorted(zip(FEATURES, imp), key=lambda t: -t[1]):
        log(f"{nome:<20}: {v:.3f}")

    if salvar:
        # Modelo FINAL: treina com todos os dados, salva e registra o hash.
        final = criar_pipeline().fit(X, y)
        joblib.dump(final, MODELO_PATH)
        digest = registrar_hash()
        log(f"\nModelo salvo em: {MODELO_PATH.name}")
        log(f"SHA-256: {digest}")
        METRICAS_PATH.write_text("\n".join(linhas) + "\n", encoding="utf-8")
    return metricas


if __name__ == "__main__":
    treinar_e_avaliar()
