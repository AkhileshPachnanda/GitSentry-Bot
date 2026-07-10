import { useState, useMemo } from 'react';
import { useDashboardStore } from '../stores/useDashboardStore';
import { AlertTriangle, Copy, CheckCircle2, ArrowUpDown } from 'lucide-react';
import FilterBar from './FilterBar';

const SeverityBadge = ({ severity }) => {
  const sev = severity?.toLowerCase() || 'low';
  const colors = {
    critical: 'bg-accent-red/10 text-accent-red border-accent-red/20',
    high: 'bg-accent-orange/10 text-accent-orange border-accent-orange/20',
    medium: 'bg-accent-yellow/10 text-accent-yellow border-accent-yellow/20',
    low: 'bg-accent-green/10 text-accent-green border-accent-green/20',
  };
  const dots = {
    critical: 'bg-accent-red',
    high: 'bg-accent-orange',
    medium: 'bg-accent-yellow',
    low: 'bg-accent-green',
  };
  
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${colors[sev]}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dots[sev]}`}></span>
      <span className="capitalize">{sev}</span>
    </span>
  );
};

export default function FindingsTable() {
  const findings = useDashboardStore(state => state.findings);
  const filters = useDashboardStore(state => state.filters);
  const [copiedId, setCopiedId] = useState(null);
  const [sortConfig, setSortConfig] = useState({ key: 'created_at', direction: 'desc' });

  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      if (filters.type !== 'all' && f.category !== filters.type) return false;
      if (filters.severity.length > 0 && !filters.severity.includes(f.severity?.toLowerCase())) return false;
      if (filters.search) {
        const q = filters.search.toLowerCase();
        return f.file?.toLowerCase().includes(q) || f.type?.toLowerCase().includes(q) || f.content?.toLowerCase().includes(q);
      }
      return true;
    });
  }, [findings, filters]);

  const handleCopy = (id, text) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const sortedFindings = [...filteredFindings].sort((a, b) => {
    let aVal = a[sortConfig.key];
    let bVal = b[sortConfig.key];
    
    // Handle nulls
    if (aVal === null) aVal = '';
    if (bVal === null) bVal = '';

    if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1;
    if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1;
    return 0;
  });

  const requestSort = (key) => {
    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') direction = 'desc';
    setSortConfig({ key, direction });
  };

  return (
    <div>
      <FilterBar />
      
      <div className="glass-panel rounded-2xl overflow-hidden">
        <div className="p-5 border-b border-border flex justify-between items-center">
          <div>
            <h2 className="text-lg font-semibold text-text-primary">Detailed Findings</h2>
            <p className="text-sm text-text-secondary">Found {filteredFindings.length} issue{filteredFindings.length !== 1 && 's'}</p>
          </div>
        </div>

        {filteredFindings.length === 0 ? (
          <div className="p-12 flex flex-col items-center justify-center text-center">
            <AlertTriangle className="w-12 h-12 text-text-muted mb-4 opacity-50" />
            <h3 className="text-lg font-medium text-text-primary">No findings match your filters</h3>
            <p className="text-text-secondary mt-2">Try adjusting the search or severity filters.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="bg-bg-elevated/50 text-text-secondary text-xs uppercase tracking-wider border-b border-border">
                <tr>
                  <th className="px-6 py-4 font-medium cursor-pointer hover:text-text-primary" onClick={() => requestSort('type')}>
                    <div className="flex items-center gap-1">Type <ArrowUpDown className="w-3 h-3" /></div>
                  </th>
                  <th className="px-6 py-4 font-medium cursor-pointer hover:text-text-primary" onClick={() => requestSort('severity')}>
                    <div className="flex items-center gap-1">Severity <ArrowUpDown className="w-3 h-3" /></div>
                  </th>
                  <th className="px-6 py-4 font-medium cursor-pointer hover:text-text-primary" onClick={() => requestSort('file')}>
                    <div className="flex items-center gap-1">Location <ArrowUpDown className="w-3 h-3" /></div>
                  </th>
                  <th className="px-6 py-4 font-medium cursor-pointer hover:text-text-primary" onClick={() => requestSort('content')}>
                    <div className="flex items-center gap-1">Snippet / Details <ArrowUpDown className="w-3 h-3" /></div>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {sortedFindings.slice(0, 50).map((finding) => (
                  <tr key={finding.id} className="hover:bg-bg-elevated/30 transition-colors group">
                    <td className="px-6 py-4">
                      <div className="font-medium text-text-primary">{finding.type}</div>
                      <div className="text-xs text-text-muted capitalize mt-1">{finding.category}</div>
                    </td>
                    <td className="px-6 py-4">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="px-6 py-4">
                      <div className="font-mono text-xs text-text-secondary break-all">
                        {finding.file || 'N/A'}
                        {finding.line && <span className="text-text-muted">:{finding.line}</span>}
                      </div>
                    </td>
                    <td className="px-6 py-4 max-w-xs">
                      {finding.category === 'secret' ? (
                        <div className="flex items-center justify-between gap-2 p-2 rounded bg-bg-elevated border border-border/50">
                          <code className="text-xs text-text-secondary truncate">{finding.content}</code>
                          <button
                            onClick={() => handleCopy(finding.id, finding.content)}
                            className="p-1.5 text-text-muted hover:text-text-primary hover:bg-border rounded transition-colors"
                            title="Copy snippet"
                          >
                            {copiedId === finding.id ? <CheckCircle2 className="w-3.5 h-3.5 text-accent-green" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      ) : (
                        <div className="text-xs text-text-secondary">
                          {finding.cve !== 'N/A' && <span className="font-semibold text-accent-red mr-2">{finding.cve}</span>}
                          {finding.content}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
