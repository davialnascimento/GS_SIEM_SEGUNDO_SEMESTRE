import { useCallback, useEffect, useState } from 'react';
import Icon from './Icon';

const formatarPrazo = (segundos) => {
  if (!Number.isFinite(Number(segundos))) return 'Não informado';
  return new Date(Number(segundos) * 1000).toLocaleString('pt-BR', {
    dateStyle: 'short', timeStyle: 'short',
  });
};

async function consulta(path, token, options = {}) {
  const resposta = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {}),
    },
  });
  const dados = await resposta.json().catch(() => ({}));
  if (!resposta.ok) {
    const texto = typeof dados.detail === 'string' ? dados.detail : `Falha (${resposta.status})`;
    throw new Error(resposta.status === 401 ? 'Sessão expirada. Entre novamente.' : texto);
  }
  return dados;
}

export default function PainelAcessos({ token, usuarioAtual }) {
  const [usuarios, setUsuarios] = useState([]);
  const [convites, setConvites] = useState([]);
  const [novoConvite, setNovoConvite] = useState('');
  const [ocupado, setOcupado] = useState('');
  const [carregando, setCarregando] = useState(true);
  const [erro, setErro] = useState('');
  const [mensagem, setMensagem] = useState('');
  const [copiado, setCopiado] = useState(false);

  const carregar = useCallback(async () => {
    const [lista, emitidos] = await Promise.all([
      consulta('/api/admin/usuarios', token),
      consulta('/api/admin/convites', token),
    ]);
    setUsuarios(Array.isArray(lista.usuarios) ? lista.usuarios : []);
    setConvites(Array.isArray(emitidos.convites) ? emitidos.convites : []);
  }, [token]);

  useEffect(() => {
    let ativo = true;
    // O estado inicial ja informa carregamento e nenhum erro.
    Promise.all([
      consulta('/api/admin/usuarios', token),
      consulta('/api/admin/convites', token),
    ]).then(([lista, emitidos]) => {
      if (!ativo) return;
      setUsuarios(Array.isArray(lista.usuarios) ? lista.usuarios : []);
      setConvites(Array.isArray(emitidos.convites) ? emitidos.convites : []);
    }).catch((e) => { if (ativo) setErro(e.message); })
      .finally(() => { if (ativo) setCarregando(false); });
    return () => { ativo = false; };
  }, [token]);

  async function executar(tipo, operacao) {
    setOcupado(tipo);
    setMensagem('');
    setErro('');
    try {
      await operacao();
    } catch (e) {
      setErro(e.message || 'Não foi possível completar a ação.');
    } finally {
      setOcupado('');
    }
  }

  async function criarConvite() {
    await executar('convite', async () => {
      const resultado = await consulta('/api/convites', token, { method: 'POST' });
      if (!resultado.convite) throw new Error('O servidor não retornou um convite válido.');
      setNovoConvite(resultado.convite);
      setCopiado(false);
      await carregar();
      setMensagem('Convite gerado. Compartilhe o código apenas com a pessoa autorizada.');
    });
  }

  async function copiarConvite() {
    if (!novoConvite) return;
    try {
      await navigator.clipboard.writeText(novoConvite);
      setCopiado(true);
      setMensagem('Código copiado. Ele só será mostrado nesta sessão.');
    } catch {
      setErro('O navegador bloqueou a cópia. Selecione o código e copie manualmente.');
    }
  }

  async function revogarConvite(id) {
    if (!window.confirm('Revogar este convite? Ele não poderá mais ser usado.')) return;
    await executar('revogar', async () => {
      await consulta(`/api/admin/convites/${encodeURIComponent(id)}`, token, { method: 'DELETE' });
      await carregar();
      // O convite recém-criado não precisa permanecer à mostra após uma revogação.
      setNovoConvite('');
      setMensagem('Convite revogado.');
    });
  }

  async function alterarUsuario(usuario, ativo) {
    if (!window.confirm(`${ativo ? 'Ativar' : 'Suspender'} o acesso de ${usuario}?`)) return;
    await executar(`usuario-${usuario}`, async () => {
      await consulta(`/api/admin/usuarios/${encodeURIComponent(usuario)}/status`, token, {
        method: 'PATCH', body: JSON.stringify({ ativo }),
      });
      await carregar();
      setMensagem(`Acesso de ${usuario} ${ativo ? 'ativado' : 'suspenso'}.`);
    });
  }

  return (
    <div className="admin-content">
      <section className="admin-overview" aria-labelledby="access-title">
        <div>
          <span className="eyebrow">CONTROLE DE ACESSO</span>
          <h2 id="access-title">Pessoas e permissões</h2>
          <p>Gerencie quem pode entrar no ambiente. Convites são individuais, de uso único e expiram após 24 horas.</p>
        </div>
        <button className="btn btn-primary" type="button" onClick={criarConvite} disabled={!!ocupado || carregando}>
          <Icon name="plus" size={17} />{ocupado === 'convite' ? 'Gerando...' : 'Novo convite'}
        </button>
      </section>

      {erro && <div className="notice notice-error" role="alert"><Icon name="alert" size={18} />{erro}<button className="inline-link" type="button" onClick={() => executar('atualizar', carregar)}>Tentar novamente</button></div>}
      {mensagem && <div className="notice notice-success" role="status"><Icon name="check" size={18} />{mensagem}</div>}
      {carregando && <div className="admin-loading" role="status"><span className="loading-spinner" />Carregando acessos...</div>}

      {novoConvite && <section className="surface admin-new-invite" aria-labelledby="new-invite-title">
        <div className="section-head"><div><span className="eyebrow">CONVITE RECÉM-CRIADO</span><h3 id="new-invite-title">Compartilhe com segurança</h3></div><button className="icon-button" title="Ocultar código" aria-label="Ocultar código" onClick={() => setNovoConvite('')}><Icon name="x" size={18}/></button></div>
        <p>Este código é exibido somente agora. Ele não ficará visível na lista de convites e permite criar uma conta de analista.</p>
        <div className="invite-secret-row"><input type="text" aria-label="Código de convite criado" readOnly value={novoConvite} onFocus={e => e.target.select()} /><button type="button" className="btn btn-primary" onClick={copiarConvite}>{copiado ? 'Copiado' : 'Copiar código'}</button></div>
        <p className="footnote">Não inclua o código em prints, vídeos ou arquivos enviados ao GitHub.</p>
      </section>}

      <div className="admin-grid">
        <section className="surface" aria-labelledby="users-title">
          <div className="section-head"><div><span className="eyebrow">USUÁRIOS</span><h3 id="users-title">Contas do ambiente</h3></div><span className="section-note">{usuarios.length} contas</span></div>
          <div className="admin-account-list">
            {usuarios.map(conta => <div className="admin-account" key={conta.usuario}>
              <div className="admin-avatar"><Icon name="user" size={18}/></div>
              <div className="admin-account-details"><strong>{conta.usuario}{conta.usuario === usuarioAtual && <span className="admin-self">Você</span>}</strong><small>{conta.papel === 'admin' ? 'Administrador' : 'Analista'} · {conta.ativo ? 'Acesso ativo' : 'Acesso suspenso'}</small></div>
              {conta.papel !== 'admin' ? <button type="button" className="btn btn-secondary admin-account-action" disabled={!!ocupado} onClick={() => alterarUsuario(conta.usuario, !conta.ativo)}>{conta.ativo ? 'Suspender' : 'Reativar'}</button> : <span className="admin-protected">Protegido</span>}
            </div>)}
            {!usuarios.length && !carregando && <div className="empty-mini">Nenhuma conta retornada pelo backend.</div>}
          </div>
          <p className="footnote">Suspender uma conta bloqueia novas entradas e invalida o uso de sessões existentes na próxima requisição.</p>
        </section>
        <section className="surface" aria-labelledby="invites-title">
          <div className="section-head"><div><span className="eyebrow">CONVITES</span><h3 id="invites-title">Convites pendentes</h3></div><span className="section-note">{convites.length} ativos</span></div>
          <p className="admin-explain">Por segurança, os códigos completos não são armazenados em texto legível. Aqui você pode acompanhar e revogar convites ainda válidos.</p>
          <div className="admin-invite-list">
            {convites.map(c => <div className="admin-invite" key={c.id}>
              <div><strong className="mono">Convite • {String(c.id).slice(0, 9)}</strong><small>Expira em {formatarPrazo(c.expira_em)}</small></div>
              <button type="button" className="text-action" disabled={!!ocupado} onClick={() => revogarConvite(c.id)}>Revogar <Icon name="x" size={14}/></button>
            </div>)}
            {!convites.length && !carregando && <div className="admin-empty"><Icon name="key" size={23}/><strong>Sem convites pendentes</strong><p>Gere um convite quando um novo analista precisar de acesso.</p></div>}
          </div>
        </section>
      </div>
      <section className="admin-info-strip"><Icon name="shield" size={18}/><p>As permissões são verificadas no servidor. O frontend apenas apresenta as opções autorizadas.</p></section>
    </div>
  );
}
