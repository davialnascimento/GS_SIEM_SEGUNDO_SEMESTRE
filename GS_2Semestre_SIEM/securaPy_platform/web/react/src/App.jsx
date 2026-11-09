import { useEffect, useMemo, useRef, useState } from 'react';
import Icon from './Icon';
import PainelOperacoes from './PainelOperacoes';
import PainelAcessos from './PainelAcessos';
import ResumoExecutivo from './ResumoExecutivo';
import './index.css';
import './ux2.css';

const LOGO = '/viotrace-logo.png';
const NIVEIS = ['CRITICA', 'ALTA', 'MEDIA', 'BAIXA', 'INFO'];
const LISTA_VAZIA = Object.freeze([]);
const NOMES = { CRITICA: 'Crítica', ALTA: 'Alta', MEDIA: 'Média', BAIXA: 'Baixa', INFO: 'Informativa' };
const paginas = {
  dashboard: { label: 'Visão geral', icon: 'dashboard', caption: 'Panorama da operação' },
  alertas: { label: 'Alertas', icon: 'alert', caption: 'Ocorrências e evidências' },
  inteligencia: { label: 'Inteligência de IPs', icon: 'radar', caption: 'Contexto de ameaças' },
  operacoes: { label: 'Operações SIEM', icon: 'terminal', caption: 'Execução e configurações' },
  assistente: { label: 'VIX', icon: 'bot', caption: 'Análise assistida por Llama 3.2' },
  acessos: { label: 'Acessos e convites', icon: 'users', caption: 'Usuários, permissões e convites' },
};
const menuGrupos = [
  { titulo: 'MONITORAMENTO', ids: ['dashboard', 'alertas', 'inteligencia'] },
  { titulo: 'FERRAMENTAS', ids: ['operacoes', 'assistente'] },
];

function nivel(valor) {
  return String(valor || 'INFO').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase();
}
function textoData(valor) {
  if (!valor) return 'Ainda não disponível';
  return String(valor).replace('T', ' ').slice(0, 19);
}
function textoHora(valor) {
  const texto = String(valor || '');
  return texto.includes(' ') ? texto.split(' ')[1]?.slice(0, 8) : texto.includes('T') ? texto.split('T')[1]?.slice(0, 8) : texto || '—';
}
function textoErro(json, padrao) { return typeof json?.detail === 'string' ? json.detail : padrao; }

function Badge({ value, small = false }) {
  const s = nivel(value);
  return <span className={`severity severity--${s.toLowerCase()}${small ? ' severity--small' : ''}`}><span className="severity-dot" />{NOMES[s] || s}</span>;
}
function Botao({ children, icon, secondary = false, ...props }) {
  return <button className={secondary ? 'btn btn-secondary' : 'btn btn-primary'} {...props}>{icon && <Icon name={icon} size={16} />}{children}</button>;
}
function Vazio({ title = 'Nenhum resultado encontrado', description = 'Ajuste os filtros ou processe novos logs.', icon = 'search' }) {
  return <div className="empty"><span className="empty-icon"><Icon name={icon} size={22} /></span><strong>{title}</strong><p>{description}</p></div>;
}
function NavLogo() {
  return <div className="brand"><div className="brand-symbol"><img src={LOGO} alt="" /></div><div className="brand-text"><strong>VioTrace</strong><span>SECURITY INTELLIGENCE</span></div></div>;
}
function SecurityTable({ items, onInvestigate, compact = false }) {
  if (!items.length) return <Vazio title="Sem alertas neste recorte" description="Experimente outros filtros ou processe os logs novamente." />;
  return <div className="table-wrap"><table className={`data-table ux-alert-table ${compact ? 'data-table-compact' : ''}`}>
    <thead><tr><th>Data / hora</th><th>Detecção</th><th>Endereço IP</th><th>Severidade</th>{!compact && <th>País</th>}<th className="col-action">Ação</th></tr></thead>
    <tbody>{items.map((a, idx) => <tr key={`${a.timestamp}-${a.ip}-${a.regra_id || ''}-${idx}`}>
      <td className="time-cell" data-label="Data / hora">{textoData(a.timestamp)}</td>
      <td data-label="Detecção"><div className="event-title">{a.regra_nome || 'Alerta sem regra'}</div>{!compact && <div className="event-description">{a.descricao || 'Sem descrição'}</div>}</td>
      <td data-label="Endereço IP"><span className="mono">{a.ip || '—'}</span></td>
      <td data-label="Severidade"><Badge value={a.severidade} small /></td>
      {!compact && <td className="subtle-cell" data-label="País">{a.geolocalizacao?.pais || '—'}</td>}
      <td data-label="Ação"><button type="button" className="icon-button row-action" disabled={!a.ip} title={`Investigar ${a.ip || 'IP'}`} aria-label={`Investigar IP ${a.ip || ''}`} onClick={() => onInvestigate(a.ip)}><Icon name="arrow" size={17} /></button></td>
    </tr>)}</tbody>
  </table></div>;
}
function InlineText({ children }) {
  // Mostra marcação simples do LLM sem injetar HTML não confiável.
  return String(children).split(/(\*\*[^*]+\*\*)/g).map((p, i) => p.startsWith('**') && p.endsWith('**') ? <strong key={i}>{p.slice(2, -2)}</strong> : <span key={i}>{p}</span>);
}
function AnswerText({ value }) {
  return <div className="answer-text">{String(value).split(/\n+/).filter(Boolean).map((line, i) => <p key={i}><InlineText>{line.replace(/^\s*[-*]\s+/, '• ').replace(/^\s*#+\s*/, '')}</InlineText></p>)}</div>;
}

export default function App() {
  const [token, setToken] = useState(null);
  const [usuarioAtivo, setUsuarioAtivo] = useState('');
  const [ehAdmin, setEhAdmin] = useState(false);
  const [loginUsuario, setLoginUsuario] = useState('');
  const [loginSenha, setLoginSenha] = useState('');
  const [entrando, setEntrando] = useState(false);
  const [erroLogin, setErroLogin] = useState('');
  const [cadastroVisivel, setCadastroVisivel] = useState(false);
  const [novoUsuario, setNovoUsuario] = useState('');
  const [novaSenha, setNovaSenha] = useState('');
  const [confirmarSenha, setConfirmarSenha] = useState('');
  const [codigoConvite, setCodigoConvite] = useState('');
  const [cadastrando, setCadastrando] = useState(false);
  const [erroCadastro, setErroCadastro] = useState('');
  const [sucessoCadastro, setSucessoCadastro] = useState('');
  const [menuAberto, setMenuAberto] = useState(false);
  const [feedback, setFeedback] = useState('');
  const [pagina, setPagina] = useState('dashboard');
  const [abaOperacoes, setAbaOperacoes] = useState('eventos');
  const [dados, setDados] = useState(null);
  const [erroDados, setErroDados] = useState('');
  const [carregandoDados, setCarregandoDados] = useState(false);
  const [buscaAlerta, setBuscaAlerta] = useState('');
  const [severidade, setSeveridade] = useState('TODAS');
  const [paginaAlertas, setPaginaAlertas] = useState(1);
  const [buscaIp, setBuscaIp] = useState('');
  const [ipSelecionado, setIpSelecionado] = useState(null);
  const [ipEmAnalise, setIpEmAnalise] = useState('');
  const [mensagens, setMensagens] = useState([]);
  const [pergunta, setPergunta] = useState('');
  const [enviando, setEnviando] = useState(false);
  const [erroIa, setErroIa] = useState('');
  const chatFim = useRef(null);

  async function request(path, options = {}, authToken = token) {
    const response = await fetch(path, { ...options, headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}), ...(options.headers || {}) } });
    const json = await response.json().catch(() => ({}));
    if (response.status === 401 && authToken) {
      setToken(null); setDados(null); setMensagens([]);
      throw new Error('Sua sessão expirou. Entre novamente.');
    }
    if (!response.ok) throw new Error(textoErro(json, `Falha na requisição (${response.status}).`));
    return json;
  }
  async function atualizarRelatorio(t = token) {
    setCarregandoDados(true); setErroDados('');
    try {
      const json = await request('/api/relatorio', {}, t);
      if (!Array.isArray(json.alertas)) throw new Error('A API retornou um relatório sem lista de alertas.');
      setDados(json);
      setFeedback('Relatório sincronizado com o backend.');
    } catch (e) { setErroDados(e.message); throw e; }
    finally { setCarregandoDados(false); }
  }
  useEffect(() => {
    if (!token) return;
    let ativo = true;
    fetch('/api/relatorio', { headers: { Authorization: `Bearer ${token}` } })
      .then(async r => {
        if (r.status === 401) { setToken(null); throw new Error('Sessão expirada.'); }
        if (!r.ok) throw new Error('Não foi possível carregar o relatório protegido.');
        return r.json();
      }).then(j => { if (ativo) { if (!Array.isArray(j.alertas)) throw new Error('Relatório inválido.'); setDados(j); setErroDados(''); } })
      .catch(e => { if (ativo && token) setErroDados(e.message); });
    return () => { ativo = false; };
  }, [token]);
  useEffect(() => {
    if (!ipSelecionado) return;
    const anterior = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const esc = e => { if (e.key === 'Escape') setIpSelecionado(null); };
    window.addEventListener('keydown', esc);
    return () => { document.body.style.overflow = anterior; window.removeEventListener('keydown', esc); };
  }, [ipSelecionado]);
  useEffect(() => { chatFim.current?.scrollIntoView({ behavior: 'smooth', block: 'end' }); }, [mensagens, enviando]);
  useEffect(() => {
    if (!feedback) return;
    const timer = window.setTimeout(() => setFeedback(''), 4400);
    return () => window.clearTimeout(timer);
  }, [feedback]);

  async function entrar(e) {
    e.preventDefault(); setEntrando(true); setErroLogin('');
    try {
      const j = await request('/api/login', { method: 'POST', body: JSON.stringify({ usuario: loginUsuario.trim(), senha: loginSenha }) }, null);
      if (!j.token) throw new Error('O servidor não retornou uma sessão válida.');
      setUsuarioAtivo(j.usuario || loginUsuario.trim()); setEhAdmin(j.papel === 'admin'); setPagina('dashboard');
      setLoginSenha(''); setSucessoCadastro(''); setDados(null); setErroDados(''); setToken(j.token);
    } catch (e) { setErroLogin(e.message === 'Failed to fetch' ? 'Não foi possível conectar ao backend Python.' : e.message); }
    finally { setEntrando(false); }
  }
  async function cadastrarConta(e) {
    e.preventDefault(); setErroCadastro('');
    if (novaSenha !== confirmarSenha) { setErroCadastro('As senhas não coincidem.'); return; }
    setCadastrando(true);
    try {
      await request('/api/cadastro', { method: 'POST', body: JSON.stringify({ usuario: novoUsuario.trim(), senha: novaSenha, convite: codigoConvite.trim() }) }, null);
      setSucessoCadastro('Conta criada. Entre com seu novo usuário.'); setLoginUsuario(novoUsuario.trim());
      setNovaSenha(''); setConfirmarSenha(''); setCodigoConvite(''); setNovoUsuario(''); setCadastroVisivel(false);
    } catch (e) { setErroCadastro(e.message === 'Failed to fetch' ? 'Servidor offline. Verifique o backend.' : e.message); }
    finally { setCadastrando(false); }
  }
  async function sair() {
    const anterior = token;
    setToken(null); setDados(null); setMensagens([]); setIpSelecionado(null); setPagina('dashboard'); setFeedback('');
    try { await fetch('/api/logout', { method: 'POST', headers: { Authorization: `Bearer ${anterior}` } }); } catch { /* Sessão já descartada no frontend. */ }
  }
  function navegar(nova, aba = 'eventos') { setPagina(nova); if (nova === 'operacoes') setAbaOperacoes(aba); setIpSelecionado(null); setMenuAberto(false); window.scrollTo({ top: 0, behavior: 'auto' }); }
  function abrirIp(ip) { if (ip) setIpSelecionado(ip); }
  function analisarComIA(ip) {
    if (!ip) return;
    setIpEmAnalise(ip); setIpSelecionado(null); setErroIa(''); setPagina('assistente'); window.scrollTo(0, 0);
    setPergunta(`Analise as evidências e detecções correlacionadas do IP ${ip}. Diferencie fatos de hipóteses e recomende ações defensivas.`);
  }
  async function enviarPergunta(e) {
    e?.preventDefault();
    const texto = pergunta.trim(); if (!texto || enviando) return;
    const historico = mensagens.slice(-6).map(m => ({ role: m.papel === 'usuario' ? 'user' : 'assistant', content: m.texto.slice(0, 700) }));
    setMensagens(m => [...m, { papel: 'usuario', texto }]); setPergunta(''); setErroIa(''); setEnviando(true);
    try {
      const j = await request('/api/assistente', { method: 'POST', body: JSON.stringify({ pergunta: texto, ip: ipEmAnalise || null, historico }) });
      if (typeof j.resposta !== 'string') throw new Error('A IA não retornou uma resposta válida.');
      setMensagens(m => [...m, { papel: 'assistente', texto: j.resposta }]);
    } catch (e) { setErroIa(e.message === 'Failed to fetch' ? 'O backend ou o Ollama não está disponível.' : e.message); }
    finally { setEnviando(false); }
  }

  // Evita criar arrays novos em cada renderizacao.
  const alertas = Array.isArray(dados?.alertas) ? dados.alertas : LISTA_VAZIA;
  const eventos = Array.isArray(dados?.eventos) ? dados.eventos : LISTA_VAZIA;
  const correlacoes = Array.isArray(dados?.resumo_ameacas) ? dados.resumo_ameacas : LISTA_VAZIA;
  const totais = useMemo(() => Object.fromEntries(NIVEIS.map(n => [n, alertas.filter(a => nivel(a.severidade) === n).length])), [alertas]);
  const ips = useMemo(() => Object.values(alertas.reduce((mapa, a) => {
    if (!a.ip) return mapa;
    const item = mapa[a.ip] || { ip: a.ip, alertas: [], geo: null, total: 0, correlacao: null };
    item.alertas.push(a); item.total++;
    if (!item.geo && a.geolocalizacao) item.geo = a.geolocalizacao;
    mapa[a.ip] = item; return mapa;
  }, {})).map(item => ({ ...item, correlacao: correlacoes.find(c => c.ip === item.ip) || null, eventos: eventos.filter(ev => ev.ip === item.ip) })).sort((a, b) => b.total - a.total), [alertas, correlacoes, eventos]);
  const filtrados = useMemo(() => alertas.filter(a => [a.ip, a.regra_nome, a.descricao, a.regra_id].join(' ').toLowerCase().includes(buscaAlerta.toLowerCase().trim()) && (severidade === 'TODAS' || nivel(a.severidade) === severidade)), [alertas, buscaAlerta, severidade]);
  const ipsFiltrados = useMemo(() => ips.filter(i => [i.ip, i.geo?.pais, i.geo?.cidade, i.geo?.org, ...(i.correlacao?.deteccoes || [])].join(' ').toLowerCase().includes(buscaIp.toLowerCase().trim())), [ips, buscaIp]);
  const dadosIp = ips.find(i => i.ip === ipSelecionado);
  const prioridade = [...alertas].sort((a, b) => NIVEIS.indexOf(nivel(a.severidade)) - NIVEIS.indexOf(nivel(b.severidade)))[0];
  const janelaAlertas = filtrados.slice((paginaAlertas - 1) * 12, paginaAlertas * 12);
  const paginasAlertas = Math.max(1, Math.ceil(filtrados.length / 12));
  const qtd = n => totais[n] || 0;
  const ativo = paginas[pagina] || paginas.dashboard;

  // Tela de entrada e criação de conta, sem expor dados do SIEM.
  if (!token) return <main className="auth-layout">
    <section className="auth-story">
      <NavLogo />
      <div className="auth-story-content"><span className="eyebrow">SECURITY OPERATIONS PLATFORM</span><h1>Clareza diante<br />do que importa.</h1><p>Alertas, investigação e inteligência reunidos em uma única experiência para quem protege sistemas.</p><div className="auth-story-foot"><span className="auth-line" /><span>OBSERVE  /  INVESTIGUE  /  RESPONDA</span></div></div>
      <div className="auth-note"><Icon name="shield" size={16} /><span>Ambiente de laboratório · Acesso restrito</span></div>
    </section>
    <section className="auth-action"><div className="auth-panel"><span className="eyebrow">{cadastroVisivel ? 'NOVO ACESSO' : 'BEM-VINDO DE VOLTA'}</span><h2>{cadastroVisivel ? 'Criar conta' : 'Acesse o VioTrace'}</h2><p className="auth-description">{cadastroVisivel ? 'Use o convite enviado pelo administrador do ambiente.' : 'Entre para continuar sua operação de segurança.'}</p>
    {!cadastroVisivel ? <form className="auth-form" onSubmit={entrar}><label>Usuário<input autoComplete="username" value={loginUsuario} onChange={e => setLoginUsuario(e.target.value)} placeholder="Seu usuário" required /></label><label>Senha<input type="password" autoComplete="current-password" value={loginSenha} onChange={e => setLoginSenha(e.target.value)} placeholder="Sua senha" required /></label>
      {erroLogin && <p className="form-error" role="alert">{erroLogin}</p>}{sucessoCadastro && <p className="form-success" role="status">{sucessoCadastro}</p>}
      <Botao type="submit" disabled={entrando} icon="arrow">{entrando ? 'Autenticando...' : 'Entrar no painel'}</Botao><button type="button" className="text-button" onClick={() => { setCadastroVisivel(true); setErroCadastro(''); setErroLogin(''); }}>Não tem acesso? <strong>Criar conta</strong> <Icon name="arrow" size={15}/></button></form>
      : <form className="auth-form" onSubmit={cadastrarConta}><label>Novo usuário<input value={novoUsuario} onChange={e => setNovoUsuario(e.target.value)} minLength={3} maxLength={32} autoComplete="username" placeholder="Ex.: analista01" required /></label><label>Senha <small>(mínimo de 12 caracteres)</small><input type="password" value={novaSenha} onChange={e => setNovaSenha(e.target.value)} minLength={12} maxLength={128} autoComplete="new-password" required /></label><label>Confirme a senha<input type="password" value={confirmarSenha} onChange={e => setConfirmarSenha(e.target.value)} autoComplete="new-password" required /></label><label>Código de convite<input value={codigoConvite} onChange={e => setCodigoConvite(e.target.value)} placeholder="Código recebido" required /></label>{erroCadastro && <p className="form-error" role="alert">{erroCadastro}</p>}<Botao type="submit" icon="arrow" disabled={cadastrando}>{cadastrando ? 'Criando conta...' : 'Criar minha conta'}</Botao><button type="button" className="text-button" onClick={() => { setCadastroVisivel(false); setErroCadastro(''); }}>Já tem uma conta? <strong>Voltar ao login</strong></button></form>}
    <div className="auth-bottom"><Icon name="lock" size={14}/> Sessão protegida · Uso interno do laboratório</div></div></section>
  </main>;

  return <div className="shell">
    {menuAberto && <button className="mobile-scrim" aria-label="Fechar navegação" onClick={() => setMenuAberto(false)} />}
    <aside className={`app-sidebar ${menuAberto ? 'sidebar-open' : ''}`}>
      <NavLogo /><div className="sidebar-workspace"><div className="workspace-icon"><Icon name="shield" size={18}/></div><div><strong>Central de segurança</strong><span>Workspace de laboratório</span></div><Icon name="down" size={14} /></div>
      <nav className="main-nav" aria-label="Menu principal">{[...menuGrupos, ...(ehAdmin ? [{ titulo: 'ADMINISTRAÇÃO', ids: ['acessos'] }] : [])].map(g => <div className="nav-group" key={g.titulo}><span className="nav-label">{g.titulo}</span>{g.ids.map(id => <button key={id} type="button" className={`nav-item ${pagina === id ? 'nav-active' : ''}`} aria-current={pagina === id ? 'page' : undefined} onClick={() => navegar(id)}>{id === 'assistente' ? <img src="/vix_pixel_menu.png" className="vix-nav-pixel" alt="" aria-hidden="true" /> : <Icon name={paginas[id].icon} size={18}/> }<span>{paginas[id].label}</span>{pagina === id && <span className="nav-indicator"/>}</button>)}</div>)}</nav>
      <div className="sidebar-spacer" />
      <div className="sidebar-profile"><div className="avatar">{usuarioAtivo.slice(0, 1).toUpperCase()}</div><div className="profile-info"><strong>{usuarioAtivo}</strong><span>{ehAdmin ? 'Administrador' : 'Analista'}</span></div><button type="button" className="icon-button" title="Sair da conta" aria-label="Sair da conta" onClick={sair}><Icon name="logout" size={18}/></button></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><div className="topbar-left"><button className="icon-button mobile-menu" aria-label="Abrir menu" onClick={() => setMenuAberto(true)}><Icon name="menu"/></button><span>WORKSPACE</span><Icon name="chevron" size={13}/><strong>{ativo.label}</strong></div><div className="topbar-right"><span className="environment"><span/> Ambiente de laboratório</span><div className="topbar-divider"/><button type="button" className="icon-button" title="Atualizar relatório" aria-label="Atualizar relatório" onClick={() => atualizarRelatorio().catch(() => {})} disabled={carregandoDados} aria-busy={carregandoDados}><Icon name="refresh" size={17} className={carregandoDados ? 'ux-spin' : ''}/></button><span className="topbar-avatar">{usuarioAtivo.slice(0, 1).toUpperCase()}</span></div></header>
      <main className="main-content">
        <div className="page-heading"><div><span className="eyebrow">{ativo.caption}</span><h1>{ativo.label}</h1><p>{pagina === 'dashboard' ? 'Um panorama confiável do último processamento do SIEM.' : pagina === 'alertas' ? 'Alertas gerados por regras. Para comportamentos correlacionados, consulte Operações SIEM.' : pagina === 'inteligencia' ? 'Entenda a origem dos alertas e as correlações por endereço.' : pagina === 'assistente' ? 'Pergunte sobre os achados. Decida com base em evidências.' : pagina === 'acessos' ? 'Gerencie analistas e emita convites com controle administrativo.' : 'Execute análises, gerencie regras e acompanhe as transmissões.'}</p></div><div className="heading-meta"><span className="meta-label">ÚLTIMA ANÁLISE</span><span><Icon name="clock" size={14}/>{textoData(dados?.gerado_em)}</span></div></div>
        {feedback && <div className="ux-toast" role="status" aria-live="polite"><Icon name="check" size={16}/>{feedback}<button type="button" aria-label="Dispensar aviso" onClick={() => setFeedback('')}><Icon name="x" size={14}/></button></div>}
        {erroDados && <div className="notice notice-error" role="alert"><Icon name="alert" size={18}/><div><strong>Falha ao carregar os dados</strong><p>{erroDados}</p></div><button className="inline-link" onClick={() => atualizarRelatorio().catch(() => {})}>Tentar novamente</button></div>}
        {!dados && !erroDados && <div className="ux-skeleton" role="status" aria-label="Carregando relatório protegido"><div className="ux-skeleton-head"/><div className="ux-skeleton-columns"><span/><span/><span/><span/></div><div className="ux-skeleton-body"/><p>Carregando dados protegidos do SIEM...</p></div>}
        {dados && pagina === 'dashboard' && <>
          <ResumoExecutivo dados={dados} totalAlertas={alertas.length} alertasCriticos={qtd('CRITICA')} correlacoes={correlacoes} onAbrirOperacoes={() => navegar('operacoes')} onAbrirAlertas={() => navegar('alertas')} />
          {correlacoes.length > 0 && <section className="ux-correlation-brief" aria-label="Principais correlações"><div><span className="eyebrow">CORRELAÇÃO DE AMEAÇAS</span><strong>{correlacoes.length} IPs com padrões identificados</strong></div><div className="ux-correlation-items">{correlacoes.slice(0, 3).map(c => <button type="button" key={c.ip} className="ux-correlation-chip" onClick={() => abrirIp(c.ip)}><span className="mono">{c.ip}</span><Badge value={c.severidade} small /></button>)}</div><button type="button" className="text-action" onClick={() => navegar('operacoes', 'ameacas')}>Ver correlações <Icon name="arrow" size={15}/></button></section>}

          <div className="analysis-grid"><section className="surface"><div className="section-head"><div><span className="eyebrow">PERFIL DE RISCO</span><h3>Distribuição dos alertas</h3></div><span className="section-note">{alertas.length} registros</span></div><div className="severity-stack" aria-label="Distribuição proporcional por severidade">{NIVEIS.filter(n => qtd(n) > 0).map(n => <span key={n} className={`stack-item stack-${n.toLowerCase()}`} style={{ width: `${qtd(n) / alertas.length * 100}%` }} title={`${NOMES[n]}: ${qtd(n)}`} />)}</div><div className="severity-legend">{NIVEIS.map(n => <div className="legend-item" key={n}><span className={`legend-dot legend-${n.toLowerCase()}`} /><span>{NOMES[n]}</span><strong>{qtd(n)}</strong></div>)}</div><p className="footnote">Contagens referentes às regras. Detecções correlacionadas são analisadas separadamente.</p></section>
          <section className="surface focus-panel"><div className="section-head"><div><span className="eyebrow">FOCO DA INVESTIGAÇÃO</span><h3>Um sinal para acompanhar</h3></div><Icon name="radar" size={20}/></div>{prioridade ? <><Badge value={prioridade.severidade}/><h4>{prioridade.regra_nome || 'Atividade suspeita'}</h4><p>{prioridade.descricao || 'Um alerta foi registrado e merece revisão.'}</p><div className="focus-details"><span><Icon name="globe" size={15}/>{prioridade.ip || 'IP não informado'}</span><span><Icon name="clock" size={15}/>{textoHora(prioridade.timestamp)}</span></div><button className="text-action" onClick={() => abrirIp(prioridade.ip)}>Abrir investigação <Icon name="arrow" size={17}/></button></> : <Vazio icon="shield" title="Sem alertas críticos" description="Nenhum alerta foi identificado no relatório atual."/>}</section></div>
          <section className="surface table-panel"><div className="section-head"><div><span className="eyebrow">HISTÓRICO RECENTE</span><h3>Últimos alertas registrados</h3></div><button className="text-action" onClick={() => navegar('alertas')}>Ver todos <Icon name="arrow" size={16}/></button></div><SecurityTable items={[...alertas].slice(-6).reverse()} onInvestigate={abrirIp} compact /></section>
          <div className="dashboard-bottom"><section className="surface"><div className="section-head"><div><span className="eyebrow">ENDEREÇOS EM EVIDÊNCIA</span><h3>IPs com mais alertas</h3></div><button className="text-action" onClick={() => navegar('inteligencia')}>Ver análise <Icon name="arrow" size={15}/></button></div>{ips.slice(0, 5).map((it, i) => <button type="button" className="rank-row" key={it.ip} onClick={() => abrirIp(it.ip)}><span className="rank-num">{String(i + 1).padStart(2, '0')}</span><span className="mono">{it.ip}</span><span className="rank-track"><span style={{ width: `${it.total / (ips[0]?.total || 1) * 100}%` }} /></span><strong>{it.total}</strong><Icon name="chevron" size={15}/></button>)}{!ips.length && <Vazio />}</section><section className="surface methodology"><div className="section-head"><div><span className="eyebrow">SOBRE ESTA ANÁLISE</span><h3>O que está sendo observado</h3></div><Icon name="info" size={19}/></div><p>O VioTrace processa os arquivos de laboratório e apresenta os resultados da última execução. Não há captura contínua de tráfego em tempo real.</p><div className="method-list"><div><Icon name="file" size={17}/><span>Logs de autenticação, firewall e web</span></div><div><Icon name="shield" size={17}/><span>Regras individuais e correlação de eventos</span></div><div><Icon name="bot" size={17}/><span>Assistente local para interpretação dos achados</span></div></div></section></div>
        </>}
        {dados && pagina === 'alertas' && <section className="surface table-panel"><div className="section-head"><div><span className="eyebrow">ANÁLISE DE EVENTOS</span><h3>Fila de alertas</h3></div><span className="section-note">{filtrados.length} de {alertas.length} alertas</span></div><div className="filterbar"><label className="search-field"><Icon name="search" size={18}/><input type="search" placeholder="Buscar por IP, regra ou descrição" value={buscaAlerta} onChange={e => { setBuscaAlerta(e.target.value); setPaginaAlertas(1); }}/></label><label className="select-wrap"><span>Severidade</span><select value={severidade} onChange={e => { setSeveridade(e.target.value); setPaginaAlertas(1); }}><option value="TODAS">Todas</option>{NIVEIS.map(n => <option key={n} value={n}>{NOMES[n]}</option>)}</select></label>{(buscaAlerta || severidade !== 'TODAS') && <button className="clear-filters" onClick={() => { setBuscaAlerta(''); setSeveridade('TODAS'); setPaginaAlertas(1); }}>Limpar</button>}</div><SecurityTable items={janelaAlertas} onInvestigate={abrirIp}/><div className="pagination"><span>Exibindo {filtrados.length ? (paginaAlertas - 1) * 12 + 1 : 0}–{Math.min(paginaAlertas * 12, filtrados.length)} de {filtrados.length}</span><div><button disabled={paginaAlertas <= 1} onClick={() => setPaginaAlertas(n => n - 1)}>Anterior</button><span>{paginaAlertas} / {paginasAlertas}</span><button disabled={paginaAlertas >= paginasAlertas} onClick={() => setPaginaAlertas(n => n + 1)}>Próxima</button></div></div></section>}
        {dados && pagina === 'inteligencia' && <div className="intel-layout"><section className="surface"><div className="section-head"><div><span className="eyebrow">INVESTIGAÇÃO POR ENDEREÇO</span><h3>Endereços observados</h3></div><span className="section-note">{ipsFiltrados.length} IPs</span></div><label className="search-field intel-search"><Icon name="search" size={18}/><input type="search" value={buscaIp} onChange={e => setBuscaIp(e.target.value)} placeholder="Pesquisar IP, país, organização ou detecção"/></label>{ipsFiltrados.map(item => <button key={item.ip} type="button" className="intel-row" onClick={() => abrirIp(item.ip)}><div className="intel-icon"><Icon name="globe" size={19}/></div><div className="intel-row-main"><strong className="mono">{item.ip}</strong><small>{[item.geo?.cidade, item.geo?.pais].filter(Boolean).join(', ') || 'Localização não informada'}</small><div className="intel-tags">{(item.correlacao?.deteccoes || []).map((d, i) => <span key={i}>{String(d).replaceAll('_', ' ')}</span>)}</div></div><div className="intel-count"><strong>{item.total}</strong><small>alertas</small></div><Icon name="arrow" size={17}/></button>)}{!ipsFiltrados.length && <Vazio />}</section><aside className="surface intel-side"><span className="eyebrow">CONTEXTO DE SEGURANÇA</span><h3>Como interpretar</h3><div className="intel-explain"><Icon name="shield" size={18}/><div><strong>Alertas por regras</strong><p>Atividades isoladas que correspondem a padrões configurados.</p></div></div><div className="intel-explain"><Icon name="radar" size={18}/><div><strong>Correlações</strong><p>Combinações de eventos que apontam para comportamentos como brute force ou port scan.</p></div></div><div className="intel-explain"><Icon name="globe" size={18}/><div><strong>Geolocalização</strong><p>Informação associada ao IP no relatório, sujeita a imprecisões.</p></div></div><p className="footnote">Dados históricos do laboratório. A presença na blacklist refere-se à lista configurada no sistema.</p></aside></div>}
        {pagina === 'acessos' && ehAdmin && <PainelAcessos token={token} usuarioAtual={usuarioAtivo} />}
        {dados && pagina === 'operacoes' && <PainelOperacoes token={token} ehAdmin={ehAdmin} abaInicial={abaOperacoes} aoAtualizarRelatorio={atualizarRelatorio} />}
        {dados && pagina === 'assistente' && <div className="assistant-layout"><section className="assistant-main surface"><div className="assistant-header"><div className="assistant-mark vix-avatar-header"><img src={enviando ? "/vix/pensando.webp" : "/vix/neutra.webp"} alt={enviando ? "VIX pensando" : "VIX neutra"} /></div><div><h3>VIX</h3><p>Modelo local · Ollama / Llama 3.2</p></div><span className="ai-label"><span/> Assistente</span></div><div className="chat-feed" role="log" aria-live="polite" aria-label="Histórico da conversa">{!mensagens.length && <div className="chat-welcome"><div className="welcome-symbol"><Icon name="bolt" size={27}/></div><span className="eyebrow">CONVERSE COM A VIX</span><h3>Uma pergunta pode revelar<br />uma nova perspectiva.</h3><p>Investigue eventos, entenda as correlações e explore medidas defensivas com base no relatório.</p><div className="prompt-set">{['Resuma os riscos mais relevantes.', 'Quais IPs apresentam maior risco?', 'Diferencie brute force e port scan.'].map(q => <button key={q} onClick={() => setPergunta(q)}><Icon name="message" size={15}/>{q}</button>)}</div></div>}{mensagens.map((m, i) => <article key={i} className={`chat-msg ${m.papel === 'usuario' ? 'chat-user' : 'chat-assistant'}`}><div className={`msg-avatar ${m.papel === 'usuario' ? '' : 'vix-msg-avatar'}`}>{m.papel === 'usuario' ? usuarioAtivo.slice(0, 1).toUpperCase() : <img src={/(?:Análise verificada|relatório histórico de laboratório)/i.test(m.texto) ? "/vix/analisando.webp" : "/vix/falando.webp"} alt="" aria-hidden="true" />}</div><div className="msg-body"><strong>{m.papel === 'usuario' ? 'Você' : 'VIX'}</strong>{m.papel === 'usuario' ? <p>{m.texto}</p> : <AnswerText value={m.texto}/>}</div></article>)}{enviando && <div className="thinking vix-thinking"><img src="/vix/pensando.webp" alt="VIX pensando" /><span className="loading-spinner"/> VIX está pensando...</div>}<div ref={chatFim}/></div>{erroIa && <div className="notice notice-error chat-error" role="alert"><Icon name="alert" size={17}/>{erroIa}</div>}<form className="chat-composer" onSubmit={enviarPergunta}><input placeholder="Converse com a VIX ou pergunte sobre o SIEM..." value={pergunta} onChange={e => setPergunta(e.target.value)} maxLength={700} disabled={enviando} aria-label="Pergunta para a IA"/><button type="submit" disabled={enviando || !pergunta.trim()} aria-label="Enviar pergunta"><Icon name="send" size={19}/></button></form><p className="chat-disclaimer">Respostas geradas por IA podem conter erros. Confirme decisões de segurança com os dados do SIEM.</p></section><aside className="assistant-side"><section className="surface"><span className="eyebrow">CONTEXTO DA ANÁLISE</span><h3>O que a IA está lendo</h3><label className="control-label" htmlFor="ip-contexto">Filtrar por endereço IP</label><select id="ip-contexto" value={ipEmAnalise} onChange={e => setIpEmAnalise(e.target.value)}><option value="">Todos os IPs do relatório</option>{ips.map(i => <option key={i.ip} value={i.ip}>{i.ip} · {i.total} alertas</option>)}</select><div className="context-stats"><div><span>Alertas</span><strong>{ipEmAnalise ? alertas.filter(a => a.ip === ipEmAnalise).length : alertas.length}</strong></div><div><span>Relatório</span><strong>Histórico</strong></div></div><p className="footnote">O assistente usa a última análise salva no backend, incluindo detecções correlacionadas quando disponíveis.</p></section><section className="surface assistant-tip"><Icon name="info" size={18}/><p>A IA não altera regras nem bloqueia IPs. Ela oferece análise e sugestões para revisão humana.</p></section></aside></div>}
        <footer className="main-footer"><span>VioTrace © 2026</span><span>Security Operations · Ambiente educacional</span></footer>
      </main>
    </div>
    {dadosIp && <div className="drawer-backdrop" onMouseDown={e => { if (e.target === e.currentTarget) setIpSelecionado(null); }}><section className="ip-drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title"><div className="drawer-head"><div><span className="eyebrow">DETALHES DO ENDEREÇO</span><h2 id="drawer-title" className="mono">{dadosIp.ip}</h2></div><button className="icon-button" autoFocus aria-label="Fechar investigação" onClick={() => setIpSelecionado(null)}><Icon name="x"/></button></div><div className="drawer-content"><div className="drawer-highlights"><div><small>ALERTAS POR REGRAS</small><strong>{dadosIp.total}</strong></div><div><small>EVENTOS RELACIONADOS</small><strong>{dadosIp.eventos.length || '—'}</strong></div></div>{dadosIp.correlacao && <section className="drawer-block"><span className="eyebrow">DETECÇÕES CORRELACIONADAS</span><div className="intel-tags">{(dadosIp.correlacao.deteccoes || []).map((d, i) => <span key={i}>{String(d).replaceAll('_', ' ')}</span>)}</div><div className="drawer-severity"><Badge value={dadosIp.correlacao.severidade}/></div></section>}<section className="drawer-block"><span className="eyebrow">INFORMAÇÕES DE REDE</span><dl className="detail-list"><div><dt>País</dt><dd>{dadosIp.geo?.pais || 'Não informado'}</dd></div><div><dt>Cidade</dt><dd>{dadosIp.geo?.cidade || 'Não informada'}</dd></div><div><dt>Região</dt><dd>{dadosIp.geo?.regiao || 'Não informada'}</dd></div><div><dt>Organização</dt><dd>{dadosIp.geo?.org || 'Não informada'}</dd></div></dl></section><section className="drawer-block"><span className="eyebrow">ALERTAS RELACIONADOS</span><div className="drawer-alerts">{dadosIp.alertas.map((a, i) => <div key={i} className="drawer-alert"><div><strong>{a.regra_nome || 'Alerta'}</strong><span>{textoData(a.timestamp)}</span></div><Badge value={a.severidade} small /></div>)}</div></section></div><div className="drawer-actions"><Botao icon="bot" onClick={() => analisarComIA(dadosIp.ip)}>Analisar com IA</Botao><Botao secondary onClick={() => setIpSelecionado(null)}>Fechar</Botao></div></section></div>}
  </div>;
}
