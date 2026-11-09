"""Testes locais sem depender do Ollama ou de usuarios reais."""
from pathlib import Path
import sys
import unittest

RAIZ = Path(__file__).resolve().parent.parent
for _subpasta in ("api", "ia", "core", "alertas"):
    sys.path.insert(0, str(RAIZ / _subpasta))
from chat_flexivel import SISTEMA_GERAL, pergunta_usa_relatorio, pergunta_e_geral, resumo_compacto

class TestarChat(unittest.TestCase):
    def test_pergunta_pessoal_sem_relatorio(self):
        self.assertFalse(pergunta_usa_relatorio("vc gosta de mim?"))
    def test_conversa_geral_sem_relatorio(self):
        self.assertFalse(pergunta_usa_relatorio("O que é astronomia?"))
    def test_pergunta_do_siem(self):
        self.assertTrue(pergunta_usa_relatorio("Quantos alertas o VioTrace encontrou no relatório?"))
    def test_sai_de_ip_se_pergunta_pessoal(self):
        self.assertTrue(pergunta_e_geral("vc gosta de mim?"))
    def test_permanece_em_ip_se_seguranca(self):
        self.assertFalse(pergunta_e_geral("Como mitigar os alertas do IP 185.220.101.1?"))
    def test_resumo_nao_envia_logs_brutos(self):
        d = {"eventos_do_recorte": 58, "alertas_de_regras_do_recorte": 31,
             "eventos": [{"senha": "NAO_ENVIAR"}],
             "deteccoes_correlacionadas": {"ips_brute_force": ["185.220.101.1"]}}
        resultado = resumo_compacto(d)
        self.assertEqual(resultado["eventos"], 58)
        self.assertNotIn("NAO_ENVIAR", str(resultado))
        self.assertNotIn("alertas_de_regras", resultado)
    def test_prompt_admite_outros_assuntos(self):
        self.assertIn("assuntos gerais", SISTEMA_GERAL)
    def test_app_compila(self):
        codigo = (RAIZ / "api" / "app.py").read_text(encoding="utf-8-sig")
        self.assertIn("VIOTRACE_CHAT_FLEXIVEL_V1", codigo)
        compile(codigo, "app.py", "exec")

if __name__ == "__main__":
    unittest.main(verbosity=2)
