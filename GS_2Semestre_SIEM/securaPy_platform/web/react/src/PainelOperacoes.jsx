import { useCallback, useEffect, useState } from "react";
import "./operacoes.css";
import Icon from "./Icon";

async function requisitar(caminho, token, opcoes = {}) {
  const resposta = await fetch(caminho, {
    ...opcoes,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(opcoes.body ? { "Content-Type": "application/json" } : {}),
      ...(opcoes.headers || {}),
    },
  });
  if (resposta.status === 401) {
    throw new Error("Sessão expirada. Saia e entre novamente.");
  }
  const json = await resposta.json().catch(() => ({}));
  if (!resposta.ok) {
    throw new Error(typeof json.detail === "string" ? json.detail : `Erro ${resposta.status}`);
  }
  return json;
}

const NIVEIS = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"];

export default function PainelOperacoes({ token, ehAdmin, abaInicial = "eventos", aoAtualizarRelatorio }) {
  const [aba, setAba] = useState(abaInicial);
  useEffect(() => setAba(abaInicial), [abaInicial]);
  const [ocupado, setOcupado] = useState("");
  const [erro, setErro] = useState("");
  const [aviso, setAviso] = useState("");
  const [resumo, setResumo] = useState(null);
  const [regras, setRegras] = useState([]);
  const [eventos, setEventos] = useState([]);
  const [totalEventos, setTotalEventos] = useState(0);
  const [limitado, setLimitado] = useState(false);
  const [ranking, setRanking] = useState([]);
  const [origemRanking, setOrigemRanking] = useState("eventos");
  const [tcp, setTcp] = useState(null);
  const [fonte, setFonte] = useState("");
  const [tipo, setTipo] = useState("");
  const [ipFiltro, setIpFiltro] = useState("");
  const [ipInvestigado, setIpInvestigado] = useState("");
  const [investigacao, setInvestigacao] = useState(null);
  const [geoProcessar, setGeoProcessar] = useState(false);
  const [arquivoLog, setArquivoLog] = useState("auth.log");
  const [arquivoSelecionado, setArquivoSelecionado] = useState(null);
  const [historicoTcp, setHistoricoTcp] = useState([]);

  const executar = useCallback(async (rotulo, acao) => {
    setOcupado(rotulo);
    setErro("");
    setAviso("");
    try {
      const retorno = await acao();
      if (retorno?.mensagem) setAviso(retorno.mensagem);
    } catch (e) {
      setErro(e.message || "Falha inesperada.");
    } finally {
      setOcupado("");
    }
  }, []);

  const carregarResumo = useCallback(async () => {
    const [res, top] = await Promise.all([
      requisitar("/api/siem/resumo", token),
      requisitar("/api/siem/top-ips", token),
    ]);
    setResumo(res);
    setRanking(top.ips || []);
    setOrigemRanking(top.origem || "eventos");
  }, [token]);

  const carregarEventos = useCallback(async () => {
    const qs = new URLSearchParams({ limite: "5000" });
    if (fonte) qs.set("fonte", fonte);
    if (tipo.trim()) qs.set("tipo", tipo.trim());
    if (ipFiltro.trim()) qs.set("ip", ipFiltro.trim());
    const res = await requisitar(`/api/siem/eventos?${qs}`, token);
    setEventos(res.eventos || []);
    setTotalEventos(res.total || 0);
    setLimitado(Boolean(res.limitado));
  }, [token, fonte, tipo, ipFiltro]);

  const carregarRegras = useCallback(async () => {
    const res = await requisitar("/api/siem/regras", token);
    setRegras(res.regras || []);
  }, [token]);

  const carregarTcp = useCallback(async () => {
    const [status, historico] = await Promise.all([
      requisitar("/api/siem/tcp/status", token),
      requisitar("/api/siem/tcp/historico", token),
    ]);
    setTcp(status);
    setHistoricoTcp(historico.historico || []);
  }, [token]);

  useEffect(() => {
    let ativo = true;
    Promise.allSettled([carregarResumo(), carregarRegras(), carregarEventos(), carregarTcp()])
      .then((resultados) => {
        const primeiroErro = resultados.find(r => r.status === "rejected");
        if (ativo && primeiroErro) setErro(primeiroErro.reason?.message || "Falha ao carregar operações.");
      });
    return () => { ativo = false; };
    // A primeira leitura carrega os dados iniciais; filtros usam o botão Consultar.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  async function atualizarTudo() {
    await Promise.all([carregarResumo(), carregarRegras(), carregarEventos(), carregarTcp()]);
    await aoAtualizarRelatorio();
  }

  async function processarLogs() {
    await executar("processando", async () => {
      const res = await requisitar("/api/siem/processar", token, {
        method: "POST", body: JSON.stringify({ enriquecer: geoProcessar }),
      });
      await atualizarTudo();
      setAviso(`${res.mensagem} ${res.total_eventos} eventos, ${res.total_alertas} alertas.`);
    });
  }

  async function enriquecer() {
    await executar("enriquecendo", async () => {
      const res = await requisitar("/api/siem/enriquecer", token, { method: "POST" });
      await atualizarTudo();
      return res;
    });
  }

  async function enviarArquivoLog() {
    await executar("enviando-log", async () => {
      if (!arquivoSelecionado) throw new Error("Selecione um arquivo de texto primeiro.");
      if (arquivoSelecionado.size > 1_000_000) throw new Error("Tamanho máximo: 1 MB.");
      if (!window.confirm(`Substituir ${arquivoLog} pelos dados do arquivo selecionado? O original será salvo no backup privado.`)) return;
      const res = await requisitar("/api/siem/logs/enviar", token, {
        method: "POST",
        body: JSON.stringify({ arquivo: arquivoLog, conteudo: await arquivoSelecionado.text() }),
      });
      setArquivoSelecionado(null);
      return res;
    });
  }

  async function exportar() {
    await executar("exportando", async () => {
      const resposta = await fetch("/api/siem/exportar", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!resposta.ok) throw new Error("Erro ao exportar: " + resposta.status);
      const blob = await resposta.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `viotrace_${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      return { mensagem: "Relatório exportado no navegador." };
    });
  }

  function investigar() {
    executar("investigando", async () => {
      if (!ipInvestigado.trim()) throw new Error("Digite um IP antes de investigar.");
      const res = await requisitar(`/api/siem/ip/${encodeURIComponent(ipInvestigado.trim())}`, token);
      setInvestigacao(res);
      return { mensagem: `${res.eventos.length} eventos e ${res.alertas.length} alertas encontrados.` };
    });
  }

  function alterarRegra(regra) {
    executar("regra", async () => {
      const res = await requisitar(`/api/siem/regras/${encodeURIComponent(regra.id)}`, token, {
        method: "PATCH", body: JSON.stringify({ ativa: !regra.ativa }),
      });
      await carregarRegras();
      return res;
    });
  }

  function acaoTcp(acao) {
    executar("tcp", async () => {
      const res = await requisitar(`/api/siem/tcp/${acao}`, token, { method: "POST" });
      await carregarTcp();
      return res;
    });
  }

  const abas = [
    ['eventos', 'Eventos', 'file'], ['ameacas', 'Correlações', 'radar'],
    ['ips', 'Investigar IP', 'search'], ['regras', 'Regras', 'shield'], ['tcp', 'Servidor TCP', 'terminal'],
  ];
  return <div className="ops-rebuilt">
    <section className="surface ops-control">
      <div className="section-head"><div><span className="eyebrow">CENTRO DE CONTROLE</span><h3>Processamento e análise</h3></div><span className="ops-static-tag"><Icon name="database" size={15}/> Logs locais do laboratório</span></div>
      <p className="ops-explainer">Execute a leitura dos arquivos <code>securaPy/logs</code>, processe regras e correlações, ou exporte o relatório da última análise. Nenhuma das ações inicia captura contínua em tempo real.</p>
      <div className="ops-toolbar">
        <button className="btn btn-primary" disabled={!!ocupado || !ehAdmin} onClick={processarLogs}><Icon name="play" size={17}/>{ocupado === 'processando' ? 'Processando...' : 'Processar logs'}</button>
        <button className="btn btn-secondary" disabled={!!ocupado || !ehAdmin} onClick={enriquecer}><Icon name="globe" size={16}/>{ocupado === 'enriquecendo' ? 'Consultando...' : 'Enriquecer IPs'}</button>
        <button className="btn btn-secondary" disabled={!!ocupado} onClick={exportar}><Icon name="download" size={16}/>Exportar JSON</button>
        <button className="btn btn-ghost" disabled={!!ocupado} onClick={() => executar('atualizando', atualizarTudo)}><Icon name="refresh" size={16}/>Atualizar</button>
      </div>
      {ehAdmin && <div className="ops-advanced"><details><summary><Icon name="upload" size={17}/> Importar arquivo de log <Icon name="down" size={15}/></summary><div className="ops-advanced-content"><p>Selecione um arquivo de texto de até 1 MB. O arquivo original será preservado em backup no backend. Depois, execute Processar logs.</p><div className="ops-upload-controls"><label>Formato de destino<select value={arquivoLog} onChange={e => setArquivoLog(e.target.value)}><option value="auth.log">Autenticação · auth.log</option><option value="firewall.log">Firewall · firewall.log</option><option value="web_access.log">Web · web_access.log</option></select></label><label>Arquivo local<input type="file" accept=".txt,.log,text/plain" onChange={e => setArquivoSelecionado(e.target.files?.[0] || null)}/></label><button className="btn btn-secondary" onClick={enviarArquivoLog} disabled={!arquivoSelecionado || !!ocupado}>Enviar arquivo</button></div></div></details><label className="ops-check"><input type="checkbox" checked={geoProcessar} onChange={e => setGeoProcessar(e.target.checked)}/>Enriquecer IPs durante o processamento <span>(consulta externa; pode demorar)</span></label></div>}
      {!ehAdmin && <div className="ops-advisory"><Icon name="lock" size={16}/>Sua conta pode consultar e exportar. O processamento e a configuração exigem perfil de administrador.</div>}
      {ocupado && <div className="ux-ops-progress" role="status" aria-live="polite"><span className="loading-spinner"/>Operação em andamento: {({processando:'processando logs', enriquecendo:'consultando informações de IP', exportando:'preparando relatório', eventos:'filtrando eventos', investigando:'consultando IP', regra:'salvando a regra', tcp:'executando comando TCP', 'enviando-log':'enviando arquivo'})[ocupado] || 'atualizando dados'}…</div>}
      {erro && <div className="notice notice-error" role="alert"><Icon name="alert" size={18}/>{erro}</div>}
      {aviso && <div className="notice notice-success" role="status"><Icon name="check" size={18}/>{aviso}</div>}
    </section>
    <section className="ops-statline" aria-label="Estado da análise"><div><small>EVENTOS PROCESSADOS</small><strong>{resumo?.total_eventos ?? '—'}</strong></div><div><small>ALERTAS POR REGRAS</small><strong>{resumo?.total_alertas ?? '—'}</strong></div><div><small>IPs CORRELACIONADOS</small><strong>{resumo?.resumo_ameacas?.length ?? '—'}</strong></div><div><small>ÚLTIMA EXECUÇÃO</small><strong className="ops-last-run">{resumo?.gerado_em?.replace('T', ' ') || 'Sem data'}</strong></div></section>
    <div className="ops-workspace"><nav className="ops-tabs" aria-label="Seções das operações">{abas.map(([id, label, icon]) => <button key={id} type="button" className={aba === id ? 'ops-tab-active' : ''} onClick={() => { setAba(id); setErro(''); setAviso(''); }}><Icon name={icon} size={17}/>{label}</button>)}</nav>
      <div className="ops-panel">
      {aba === 'eventos' && <section className="surface ops-section"><div className="section-head"><div><span className="eyebrow">CONSULTA DE LOGS</span><h3>Eventos normalizados</h3></div><span className="section-note">{totalEventos} encontrados</span></div><form className="ops-filter" onSubmit={e => { e.preventDefault(); executar('eventos', carregarEventos); }}><label>Fonte<select value={fonte} onChange={e => setFonte(e.target.value)}><option value="">Todas as fontes</option><option value="auth">Autenticação</option><option value="firewall">Firewall</option><option value="web">Web</option></select></label><label>Tipo<input value={tipo} onChange={e => setTipo(e.target.value)} placeholder="Ex.: FAIL" /></label><label>IP exato<input value={ipFiltro} onChange={e => setIpFiltro(e.target.value)} placeholder="Ex.: 185.220.101.1" /></label><button className="btn btn-primary" type="submit" disabled={!!ocupado}><Icon name="search" size={17}/>Consultar</button></form>{limitado && <p className="ops-hint">Exibindo os primeiros 5.000 eventos da consulta.</p>}{!eventos.length ? <div className="ops-placeholder">Nenhum evento retornado. Processe os logs ou ajuste os filtros.</div> : <div className="table-wrap"><table className="data-table"><thead><tr><th>Data / hora</th><th>Fonte</th><th>Tipo</th><th>Endereço IP</th><th>Detalhes</th></tr></thead><tbody>{eventos.map((ev, i) => <tr key={i}><td className="time-cell">{ev.timestamp}</td><td>{ev.fonte}</td><td><span className="ops-event-type">{ev.tipo}</span></td><td className="mono">{ev.ip || '—'}</td><td className="ops-detail-text">{ev.detalhes || '—'}</td></tr>)}</tbody></table></div>}</section>}
      {aba === 'ameacas' && <section className="surface ops-section"><div className="section-head"><div><span className="eyebrow">PADRÕES IDENTIFICADOS</span><h3>Detecções correlacionadas</h3></div><span className="section-note">{resumo?.resumo_ameacas?.length || 0} IPs</span></div><p className="ops-hint">Estes achados combinam múltiplos eventos, diferentemente dos alertas individuais gerados pelas regras.</p><div className="table-wrap"><table className="data-table"><thead><tr><th>Endereço IP</th><th>Detecções</th><th>Severidade</th><th>Pontuação</th></tr></thead><tbody>{(resumo?.resumo_ameacas || []).map((a, i) => <tr key={i}><td className="mono">{a.ip}</td><td><div className="ops-chips">{(a.deteccoes || []).map((d, j) => <span key={j}>{String(d).replaceAll('_', ' ')}</span>)}</div></td><td><span className={`severity severity--${String(a.severidade || '').toLowerCase()}`}>{a.severidade || '—'}</span></td><td>{a.pontuacao ?? '—'}</td></tr>)}</tbody></table></div><div className="ops-two-col"><div><h4>IPs mais ativos</h4>{ranking.map((r, i) => <div className="ops-ranking-row" key={r.ip}><span>{String(i+1).padStart(2,'0')}</span><strong className="mono">{r.ip}</strong><b>{r.quantidade}</b></div>)}</div><div><h4>Alertas por severidade</h4>{NIVEIS.map(n => <div key={n} className="ops-severity-row"><span>{n}</span><strong>{resumo?.por_severidade?.[n] || 0}</strong></div>)}<p className="footnote">Ranking baseado em {origemRanking === 'eventos' ? 'eventos' : 'alertas'}.</p></div></div></section>}
      {aba === 'ips' && <section className="surface ops-section"><div className="section-head"><div><span className="eyebrow">PESQUISA DETALHADA</span><h3>Investigar endereço IP</h3></div></div><form className="ops-ip-form" onSubmit={e => { e.preventDefault(); investigar(); }}><label className="search-field"><Icon name="search" size={17}/><input value={ipInvestigado} onChange={e => setIpInvestigado(e.target.value)} placeholder="Digite um IP para investigar" aria-label="Endereço IP"/></label><button className="btn btn-primary" type="submit" disabled={!!ocupado}>Investigar <Icon name="arrow" size={16}/></button></form>{investigacao ? <><div className="ops-ip-stats"><div><small>ENDEREÇO IP</small><strong className="mono">{investigacao.ip}</strong></div><div><small>EVENTOS</small><strong>{investigacao.eventos.length}</strong></div><div><small>ALERTAS</small><strong>{investigacao.alertas.length}</strong></div></div><div className="ops-meta"><Icon name="globe" size={17}/> {investigacao.geolocalizacao?.pais || 'País não informado'} · {investigacao.geolocalizacao?.org || 'Organização não informada'}</div><h4>Eventos relacionados</h4><div className="table-wrap"><table className="data-table"><thead><tr><th>Data / hora</th><th>Fonte</th><th>Tipo</th><th>Detalhes</th></tr></thead><tbody>{investigacao.eventos.map((ev, i) => <tr key={i}><td className="time-cell">{ev.timestamp}</td><td>{ev.fonte}</td><td>{ev.tipo}</td><td>{ev.detalhes}</td></tr>)}</tbody></table></div><h4>Alertas relacionados</h4><div className="table-wrap"><table className="data-table"><thead><tr><th>Regra</th><th>Severidade</th><th>Descrição</th></tr></thead><tbody>{investigacao.alertas.map((al, i) => <tr key={i}><td>{al.regra_nome}</td><td>{al.severidade}</td><td>{al.descricao}</td></tr>)}</tbody></table></div></> : <div className="ops-placeholder">Informe um IP para consultar eventos, alertas e informações do último relatório.</div>}</section>}
      {aba === 'regras' && <section className="surface ops-section"><div className="section-head"><div><span className="eyebrow">POLÍTICAS DE DETECÇÃO</span><h3>Regras configuradas</h3></div><span className="section-note">{regras.filter(r => r.ativa).length} de {regras.length} ativas</span></div><p className="ops-hint">Alterar uma regra não reprocessa os logs automaticamente. Use <strong>Processar logs</strong> após qualquer mudança para atualizar os resultados.</p><div className="ops-rule-list">{regras.map(r => <article className="ops-rule" key={r.id}><div className="rule-id">{r.id}</div><div className="rule-detail"><h4>{r.nome}</h4><p>{r.descricao || r.condicao}</p></div><span className={`rule-state ${r.ativa ? 'rule-on' : 'rule-off'}`}><span/>{r.ativa ? 'Ativa' : 'Inativa'}</span><button type="button" className="btn btn-secondary" disabled={!ehAdmin || !!ocupado} onClick={() => alterarRegra(r)}>{r.ativa ? 'Desativar' : 'Ativar'}</button></article>)}</div></section>}
      {aba === 'tcp' && <section className="surface ops-section"><div className="section-head"><div><span className="eyebrow">COMUNICAÇÃO DE ALERTAS</span><h3>Servidor TCP</h3></div><span className={`tcp-state ${tcp?.servidor_iniciado_pelo_vio ? 'tcp-online' : ''}`}><span/>{tcp?.servidor_iniciado_pelo_vio ? 'Iniciado' : 'Não iniciado'}</span></div><p className="ops-hint">Endereço local <code>127.0.0.1:9999</code>. O botão Transmitir retransmite alertas já processados aos clientes conectados; não inicia monitoramento contínuo.</p><div className="ops-toolbar"><button className="btn btn-primary" disabled={!ehAdmin || !!ocupado} onClick={() => acaoTcp('iniciar')}><Icon name="play" size={16}/>Iniciar servidor</button><button className="btn btn-secondary" disabled={!ehAdmin || !!ocupado} onClick={() => acaoTcp('transmitir')}><Icon name="send" size={16}/>Transmitir alertas</button><button className="btn btn-ghost" disabled={!!ocupado} onClick={() => executar('tcp', carregarTcp)}><Icon name="refresh" size={16}/>Atualizar status</button></div><div className="ops-tcp-stats"><div><small>CLIENTES CONECTADOS</small><strong>{tcp?.clientes_conectados ?? '—'}</strong></div><div><small>ALERTAS ENVIADOS NA SESSÃO</small><strong>{tcp?.alertas_transmitidos_na_sessao ?? '—'}</strong></div></div><div className="ops-transmissions"><h4>Transmissões recentes</h4>{!historicoTcp.length && <div className="ops-placeholder">Nenhuma mensagem foi transmitida nesta sessão.</div>}{historicoTcp.slice(-10).reverse().map((m,i) => <p key={i} className="mono">{m}</p>)}</div><p className="footnote">Para conectar um cliente, execute <code>py cliente_alertas.py</code> na pasta securaPy em outro terminal.</p></section>}
      </div>
    </div>
  </div>;
}
