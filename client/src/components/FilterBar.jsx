import { Search, X } from 'lucide-react';
import { useDashboardStore } from '../stores/useDashboardStore';

export default function FilterBar() {
  const filters = useDashboardStore(state => state.filters);
  const setFilter = useDashboardStore(state => state.setFilter);
  const clearFilters = useDashboardStore(state => state.clearFilters);

  const toggleSeverity = (sev) => {
    if (filters.severity.includes(sev)) {
      setFilter('severity', filters.severity.filter(s => s !== sev));
    } else {
      setFilter('severity', [...filters.severity, sev]);
    }
  };

  const hasFilters = filters.search || filters.severity.length > 0 || filters.type !== 'all';

  return (
    <div className="flex flex-col md:flex-row gap-4 items-center justify-between mb-6 p-4 glass-panel rounded-xl">
      <div className="relative w-full md:w-96">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Search className="w-4 h-4 text-text-muted" />
        </div>
        <input
          type="text"
          placeholder="Search findings by file, type, content..."
          className="w-full pl-10 pr-4 py-2 bg-bg-elevated border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent-orange focus:ring-1 focus:ring-accent-orange transition-colors placeholder:text-text-muted"
          value={filters.search}
          onChange={(e) => setFilter('search', e.target.value)}
        />
      </div>

      <div className="flex items-center gap-3 w-full md:w-auto overflow-x-auto pb-2 md:pb-0">
        <div className="flex gap-2">
          {['critical', 'high', 'medium', 'low'].map(sev => (
            <button
              key={sev}
              onClick={() => toggleSeverity(sev)}
              className={`px-3 py-1.5 rounded-full text-xs font-medium capitalize border transition-colors ${
                filters.severity.includes(sev)
                  ? 'bg-bg-elevated border-border-strong text-text-primary'
                  : 'bg-transparent border-border text-text-secondary hover:text-text-primary hover:border-border-strong'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="w-px h-6 bg-border mx-1"></div>

        <select
          value={filters.type}
          onChange={(e) => setFilter('type', e.target.value)}
          className="bg-bg-elevated border border-border rounded-lg px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent-orange"
        >
          <option value="all">All Types</option>
          <option value="secret">Secrets</option>
          <option value="dependency">Dependencies</option>
        </select>

        {hasFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1 px-3 py-1.5 text-sm text-text-muted hover:text-text-primary transition-colors whitespace-nowrap"
          >
            <X className="w-4 h-4" /> Clear
          </button>
        )}
      </div>
    </div>
  );
}
