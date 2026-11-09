import Icon from './Icon';

function CardIndicador({ label, value, detail, tone = '' }) {
  return <div className={`ux-metric ${tone}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>;
}

export default function ResumoExecutivo({ dados, totalAlertas, alertasCriticos, correlacoes, onAbrirOperacoes, onAbrirAlertas }) {
  const correlacionadosCriticos = correlacoes.filter(a =>
    String(a?.severidade || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase() === 'CRITICA'
  ).length;

  return <>
    <section className="ux-overview-lead">
      <div className="ux-overview-text"><span className="eyebrow">ÚLTIMA ANÁLISE</span><h2>Seu ambiente, em perspectiva.</h2><p>Comece pelos sinais prioritários e aprofunde a investigação quando necessário.</p></div>
      <div className="ux-overview-actions"><button className="btn btn-primary" onClick={onAbrirOperacoes}><Icon name="play" size={16}/>Executar análise</button><button className="btn btn-secondary" onClick={onAbrirAlertas}>Ver alertas <Icon name="arrow" size={16}/></button></div>
    </section>
    <section className="ux-metrics" aria-label="Indicadores da última análise">
      <CardIndicador label="Eventos analisados" value={dados?.total_eventos ?? '—'} detail="Registros de log" />
      <CardIndicador label="Alertas por regras" value={dados?.total_alertas ?? totalAlertas} detail="Detecções individuais" />
      <CardIndicador label="Alertas críticos" value={alertasCriticos} detail="Severidade das regras" tone="ux-metric-red" />
      <CardIndicador label="IPs com correlação" value={correlacoes.length} detail={`${correlacionadosCriticos} classificados como críticos`} tone="ux-metric-violet" />
    </section>
    <div className="ux-difference" role="note"><Icon name="info" size={17}/><span><strong>Dois níveis de análise:</strong> alertas por regras indicam eventos individuais; correlações relacionam comportamentos por IP. Seus totais não são intercambiáveis.</span></div>
  </>;
}
