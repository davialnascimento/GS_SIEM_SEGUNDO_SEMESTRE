"""BÔNUS (+0,30): detecção de anomalias com Isolation Forest.

Diferente do classificador (supervisionado, aprende "o que é ataque"), o
Isolation Forest aprende o que é tráfego NORMAL e marca como anomalia o que
foge do padrão — inclusive ataques que as regras e o classificador nunca viram.

    from ml.anomalias import detectar_anomalias
    anomalos = detectar_anomalias(ameacas)   # {ip: {"anomalia": True, "score": -0.21}}
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.features import normalizar_features
from ml.treinar import SEED, gerar_dataset_sintetico


def treinar_detector(contaminacao=0.05):
    """Treina só com tráfego normal (rótulo 0): sem rótulos de ataque."""
    X, y = gerar_dataset_sintetico()
    normais = X[y == 0]
    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("iso", IsolationForest(n_estimators=200, contamination=contaminacao,
                                random_state=SEED)),
    ])
    return pipe.fit(normais)


def detectar_anomalias(ameacas, detector=None):
    """{ip: features} -> {ip: {"anomalia": bool, "score": float}}.

    score menor (mais negativo) = mais anômalo. Ordenado do mais anômalo.
    """
    if not ameacas:
        return {}
    detector = detector or treinar_detector()
    ips = list(ameacas)
    X = np.array([normalizar_features(ameacas[ip]) for ip in ips])
    previsao = detector.predict(X)              # -1 = anomalia, 1 = normal
    scores = detector.decision_function(X)
    res = {ip: {"anomalia": bool(p == -1), "score": round(float(s), 4)}
           for ip, p, s in zip(ips, previsao, scores)}
    return dict(sorted(res.items(), key=lambda kv: kv[1]["score"]))
