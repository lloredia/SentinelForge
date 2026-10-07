import { useCallback, useEffect, useState } from 'react';
import { createIndicator, getIndicator, getStats, listIndicators } from './api/client';
import IocDetail from './components/IocDetail';
import IocTable from './components/IocTable';
import SearchFilters from './components/SearchFilters';
import StatsBar from './components/StatsBar';
import SubmitForm from './components/SubmitForm';
import './styles.css';

export default function App() {
  const [stats, setStats] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [selectedIndicator, setSelectedIndicator] = useState(null);
  const [enrichments, setEnrichments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('all');

  const load = useCallback(async () => {
    try {
      const [statsBody, listBody] = await Promise.all([getStats(), listIndicators()]);
      setStats(statsBody);
      setIndicators(listBody?.data || []);
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to connect to SentinelForge API');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  const handleSelectIndicator = async (indicator) => {
    setSelectedIndicator(indicator);
    try {
      const data = await getIndicator(indicator.id);
      setEnrichments(data?.enrichments || []);
      if (data?.indicator) {
        setSelectedIndicator(data.indicator);
      }
    } catch {
      setEnrichments([]);
    }
  };

  const handleAddIndicator = async (data) => {
    await createIndicator(data);
    await load();
  };

  const filteredIndicators = indicators.filter((indicator) => {
    const query = searchQuery.toLowerCase();
    const matchesSearch =
      !query ||
      indicator.value.toLowerCase().includes(query) ||
      indicator.tags?.some((tag) => tag.toLowerCase().includes(query));
    const matchesType = filterType === 'all' || indicator.ioc_type === filterType;
    return matchesSearch && matchesType;
  });

  return (
    <>
      {loading ? (
        <div className="loading">
          <div className="loading-spinner" />
          <span>Connecting to SentinelForge...</span>
        </div>
      ) : error ? (
        <div className="error-state">
          <div style={{ fontSize: '3rem' }}>⚠</div>
          <div>{error}</div>
          <button className="btn-primary" onClick={load} type="button">
            Retry Connection
          </button>
        </div>
      ) : (
        <div className={`dashboard ${selectedIndicator ? '' : 'no-detail'}`}>
          <header className="header">
            <div className="logo">
              <div className="logo-icon">SF</div>
              <div>
                <div className="logo-text">SENTINELFORGE</div>
                <div className="logo-subtitle">Threat Intelligence Platform</div>
              </div>
            </div>
            <div className="header-actions">
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                {new Date().toLocaleString()}
              </span>
              <button className="btn-primary" onClick={() => setShowAddModal(true)} type="button">
                + Add IOC
              </button>
            </div>
          </header>

          <main className="main-content">
            <StatsBar stats={stats} />
            <SearchFilters
              searchQuery={searchQuery}
              filterType={filterType}
              onSearch={setSearchQuery}
              onFilter={setFilterType}
            />
            <IocTable indicators={filteredIndicators} onSelect={handleSelectIndicator} />
          </main>

          {selectedIndicator ? (
            <IocDetail
              indicator={selectedIndicator}
              enrichments={enrichments}
              onClose={() => {
                setSelectedIndicator(null);
                setEnrichments([]);
              }}
            />
          ) : null}
        </div>
      )}

      <SubmitForm
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        onSubmit={handleAddIndicator}
      />
    </>
  );
}
