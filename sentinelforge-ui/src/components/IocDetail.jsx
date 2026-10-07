import { formatDate, iocIcons, severityStyle } from '../format';

export default function IocDetail({ indicator, enrichments, onClose }) {
  if (!indicator) return null;
  const severity = severityStyle(indicator.severity);

  return (
    <aside className="detail-panel" aria-label="Indicator detail">
      <div className="detail-header">
        <div className="detail-title">
          <span className="detail-icon">{iocIcons[indicator.ioc_type]}</span>
          <code>{indicator.value}</code>
        </div>
        <button className="close-btn" onClick={onClose} type="button" aria-label="Close detail">
          ×
        </button>
      </div>

      <div className="detail-grid">
        <div className="detail-item">
          <label>Type</label>
          <span>{String(indicator.ioc_type || '').toUpperCase()}</span>
        </div>
        <div className="detail-item">
          <label>Severity</label>
          <span
            className="severity-inline"
            style={{ background: severity.bg, color: severity.text }}
          >
            {indicator.severity}
          </span>
        </div>
        <div className="detail-item">
          <label>Confidence</label>
          <span>{indicator.confidence}%</span>
        </div>
        <div className="detail-item">
          <label>Threat Score</label>
          <span>{indicator.threat_score}/100</span>
        </div>
        <div className="detail-item">
          <label>TLP</label>
          <span className={`tlp tlp-${indicator.tlp}`}>
            {String(indicator.tlp || '').toUpperCase()}
          </span>
        </div>
        <div className="detail-item">
          <label>First Seen</label>
          <span>{formatDate(indicator.first_seen)}</span>
        </div>
        <div className="detail-item">
          <label>Last Seen</label>
          <span>{formatDate(indicator.last_seen)}</span>
        </div>
        <div className="detail-item">
          <label>ID</label>
          <code className="uuid">{indicator.id}</code>
        </div>
      </div>

      {indicator.tags?.length > 0 && (
        <div className="detail-section">
          <h4>Tags</h4>
          <div className="tags-list">
            {indicator.tags.map((tag) => (
              <span key={tag} className="tag">
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {enrichments?.length > 0 && (
        <div className="detail-section">
          <h4>Enrichment Data</h4>
          {enrichments.map((entry) => (
            <div key={`${entry.provider}-${entry.enrichment_type}`} className="enrichment-block">
              <div className="enrichment-header">
                <span className="enrichment-type">{entry.enrichment_type}</span>
                <span className="enrichment-provider">{entry.provider}</span>
              </div>
              <pre className="enrichment-data">{JSON.stringify(entry.data, null, 2)}</pre>
            </div>
          ))}
        </div>
      )}
    </aside>
  );
}
