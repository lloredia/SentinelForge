export default function SearchFilters({ searchQuery, filterType, onSearch, onFilter }) {
  return (
    <div className="toolbar">
      <div className="search-box">
        <input
          type="text"
          placeholder="Search indicators, tags..."
          value={searchQuery}
          onChange={(event) => onSearch(event.target.value)}
          aria-label="Search indicators"
        />
      </div>
      <select
        className="filter-select"
        value={filterType}
        onChange={(event) => onFilter(event.target.value)}
        aria-label="Filter by IOC type"
      >
        <option value="all">All Types</option>
        <option value="ip">IP Addresses</option>
        <option value="domain">Domains</option>
        <option value="url">URLs</option>
        <option value="hash">Hashes</option>
        <option value="email">Emails</option>
        <option value="cve">CVEs</option>
      </select>
    </div>
  );
}
