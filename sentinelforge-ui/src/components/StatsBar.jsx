function StatCard({ label, value, icon, trend }) {
  return (
    <div className="stat-card">
      <div className="stat-icon">{icon}</div>
      <div className="stat-content">
        <div className="stat-value">{Number(value || 0).toLocaleString()}</div>
        <div className="stat-label">{label}</div>
      </div>
      {trend ? (
        <div className={`stat-trend ${trend > 0 ? 'up' : 'down'}`}>
          {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}
        </div>
      ) : null}
    </div>
  );
}

export default function StatsBar({ stats }) {
  return (
    <div className="stats-bar">
      <StatCard label="Total IOCs" value={stats?.total_indicators || 0} icon="◉" />
      <StatCard
        label="New Today"
        value={stats?.new_today || 0}
        icon="+"
        trend={stats?.new_today}
      />
      <StatCard label="This Week" value={stats?.new_this_week || 0} icon="◷" />
      <StatCard label="Active Feeds" value={stats?.active_sources || 0} icon="⚡" />
      <StatCard label="Sightings (24h)" value={stats?.recent_sightings || 0} icon="👁" />
    </div>
  );
}
