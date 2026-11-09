"""Testes automatizados do Módulo C (bônus de testes com pytest).
Rode a partir da raiz do projeto:  pytest ml/test_ml.py -v
"""
import shutil

import pytest

from ml import classificar, integridade
from ml.anomalias import detectar_anomalias
from ml.features import extrair_features
from ml.treinar import gerar_dataset_sintetico, treinar_e_avaliar

ATACANTE = {"n_fails": 10, "n_portas_distintas": 7, "na_blacklist": 1, "n_web_erros": 0}
NORMAL = {"n_fails": 0, "n_portas_distintas": 1, "na_blacklist": 0, "n_web_erros": 1}


@pytest.fixture(scope="module", autouse=True)
def modelo_treinado():
    treinar_e_avaliar(verbose=False)
    classificar.limpar_cache()


def test_c1_metricas_razoaveis():
    m = treinar_e_avaliar(verbose=False)
    assert m["f1"] > 0.8 and m["recall"] > 0.8 and m["precision"] > 0.8


def test_dataset_tem_as_duas_classes():
    X, y = gerar_dataset_sintetico()
    assert X.shape[1] == 4 and set(y) == {0, 1}


def test_c2_ip_atacante_e_alto():
    r = classificar.pontuar({"185.220.101.1": ATACANTE})["185.220.101.1"]
    assert r["rotulo"] == "ataque" and r["nivel"] == "ALTO"


def test_c3_ip_normal():
    r = classificar.pontuar({"192.168.1.10": NORMAL})["192.168.1.10"]
    assert r["rotulo"] == "normal" and r["nivel"] == "BAIXO"


def test_ordenacao_por_risco():
    r = classificar.pontuar({"192.168.1.10": NORMAL, "185.220.101.1": ATACANTE})
    assert list(r)[0] == "185.220.101.1"


def test_aceita_aliases_e_listas_de_portas():
    r = classificar.pontuar({"1.2.3.4": {"fails": 10, "portas": [1, 2, 3, 4, 5, 6, 7],
                                         "blacklist": True}})
    assert r["1.2.3.4"]["rotulo"] == "ataque"


def test_entrada_vazia():
    assert classificar.pontuar({}) == {}


def test_c4_modelo_adulterado_e_detectado(tmp_path):
    modelo, hash_ = tmp_path / "m.pkl", tmp_path / "m.pkl.sha256"
    shutil.copy(integridade.MODELO_PATH, modelo)
    integridade.registrar_hash(modelo, hash_)
    assert integridade.verificar_integridade(modelo, hash_)
    with open(modelo, "ab") as f:
        f.write(b"adulterado")
    assert not integridade.verificar_integridade(modelo, hash_)
    with pytest.raises(integridade.IntegridadeError):
        classificar.carregar_modelo(modelo, hash_)


def test_c4_sem_hash_nao_carrega(tmp_path):
    modelo = tmp_path / "m.pkl"
    shutil.copy(integridade.MODELO_PATH, modelo)
    with pytest.raises(integridade.IntegridadeError):
        classificar.carregar_modelo(modelo, tmp_path / "inexistente.sha256")


def test_extrair_features_de_eventos():
    eventos = [{"fonte": "auth", "ip": "9.9.9.9", "tipo": "FAIL"}] * 3 + [
        {"fonte": "firewall", "ip": "9.9.9.9", "porta": 22},
        {"fonte": "firewall", "ip": "9.9.9.9", "porta": 80},
        {"fonte": "web", "ip": "9.9.9.9", "status": 404},
        "lixo", {"sem": "ip"},
    ]
    f = extrair_features(eventos, blacklist={"9.9.9.9"})["9.9.9.9"]
    assert f == {"n_fails": 3, "n_portas_distintas": 2, "na_blacklist": 1, "n_web_erros": 1}


def test_bonus_anomalia_detecta_atacante():
    r = detectar_anomalias({"185.220.101.1": ATACANTE, "192.168.1.10": NORMAL})
    assert r["185.220.101.1"]["anomalia"] and not r["192.168.1.10"]["anomalia"]
