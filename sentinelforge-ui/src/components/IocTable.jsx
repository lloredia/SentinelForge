import { formatDate, iocIcons, severityStyle } from '../format';

function IndicatorRow({ indicator, onClick }) {
  const severity = severityStyle(indicator.severity);
  return (
    <div
      className="indicator-row"
      onClick={() => onClick(indicator)}
      role="button"
      tabIndex={0}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onClick(indicator);
        }
      }}
    >
      <div className="ioc-type" title={indicator.ioc_type}>
        {iocIcons[indicator.ioc_type] || '?'}
      </div>
      <div className="ioc-value">
        <code>{indicator.value}</code>
      </div>
      <div
        className="severity-badge"
        style={{
          background: severity.bg,
          color: severity.text,
          boxShadow: severity.glow,
        }}
      >
        {String(indicator.severity || 'unknown').toUpperCase()}
      </div>
      <div className="threat-score">
        <div className="score-bar">
          <div className="score-fill" style={{ width: `${indicator.threat_score || 0}%` }} />
        </div>
        <span>{indicator.threat_score}</span>
      </div>
      <div className="tags">
        {indicator.tags?.slice(0, 3).map((tag) => (
          <span key={tag} className="tag">
            {tag}
          </span>
        ))}
      </div>
      <div className="timestamp">{formatDate(indicator.last_seen)}</div>
    </div>
  );
}

export default function IocTable({ indicators, onSelect }) {
  return (
    <div className="indicators-list">
      <div className="list-header">
        <span>Type</span>
        <span>Value</span>
        <span>Severity</span>
        <span>Threat Score</span>
        <span>Tags</span>
        <span>Last Seen</span>
      </div>
      {indicators.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">◉</div>
          <div>No indicators found</div>
          <div style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}>
            Add your first IOC to get started
          </div>
        </div>
      ) : (
        indicators.map((indicator) => (
          <IndicatorRow key={indicator.id} indicator={indicator} onClick={onSelect} />
        ))
      )}
    </div>
  );
}
