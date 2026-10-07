import { useState } from 'react';
import GlitchText from './GlitchText';

export default function SubmitForm({ isOpen, onClose, onSubmit }) {
  const [value, setValue] = useState('');
  const [severity, setSeverity] = useState('unknown');
  const [tags, setTags] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await onSubmit({
        value,
        severity,
        tags: tags
          ? tags
              .split(',')
              .map((tag) => tag.trim())
              .filter(Boolean)
          : [],
      });
      setValue('');
      setTags('');
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to add indicator');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-label="Add indicator"
      >
        <div className="modal-header">
          <GlitchText>ADD INDICATOR</GlitchText>
          <button className="close-btn" onClick={onClose} type="button" aria-label="Close form">
            ×
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="ioc-value">IOC Value</label>
            <input
              id="ioc-value"
              type="text"
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder="IP, domain, hash, URL, email, or CVE..."
              required
              autoFocus
            />
            <span className="input-hint">Type auto-detected from value</span>
          </div>
          <div className="form-group">
            <label htmlFor="ioc-severity">Severity</label>
            <select
              id="ioc-severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <option value="unknown">Unknown</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div className="form-group">
            <label htmlFor="ioc-tags">Tags</label>
            <input
              id="ioc-tags"
              type="text"
              value={tags}
              onChange={(event) => setTags(event.target.value)}
              placeholder="phishing, malware, c2 (comma separated)"
            />
          </div>
          {error ? (
            <p className="form-error" role="alert">
              {error}
            </p>
          ) : null}
          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Adding...' : 'Add Indicator'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
