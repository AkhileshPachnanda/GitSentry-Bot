import { useState } from 'react';
import { useDashboardStore } from '../stores/useDashboardStore';
import { ArrowUpDown, ShieldCheck, ShieldAlert, GitPullRequest } from 'lucide-react';

export default function ScansTable() {
  const scans = useDashboardStore(state => state.scans);
  const [sortConfig, setSortConfig] = useState({ key: 'created_at', direction: 'desc' });

  const sortedScans = [...scans].sort((a, b) => {
    if (a[sortConfig.key] < b[sortConfig.key]) return sortConfig.direction === 'asc' ? -1 : 1;
    if (a[sortConfig.key] > b[sortConfig.key]) return sortConfig.direction === 'asc' ? 1 : -1;
    return 0;
  });

  const requestSort = (key) => {
    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
  };

  if (!scans || scans.length === 0) {
    return (
      <div className="glass-panel rounded-2xl p-12 flex flex-col items-center justify-center text-center">
        <GitPullRequest className="w-12 h-12 text-text-muted mb-4 opacity-50" />
        <h3 className="text-lg font-medium text-text-primary">No scans recorded yet</h3>
        <p className="text-text-secondary mt-2 max-w-md">
          Install the GitSentry app on your GitHub repositories to start seeing automated security scans here.
        </p>
      </div>
    );
  }

  return (
    <div className="glass-panel rounded-2xl overflow-hidden">
      <div className="p-5 border-b border-border flex justify-between items-center">
        <div>
          <h2 className="text-lg font-semibold text-text-primary">Recent Scans</h2>
          <p className="text-sm text-text-secondary">Webhook activity and pull request checks</p>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="bg-bg-elevated/50 text-text-secondary text-xs uppercase tracking-wider border-b border-border">
            <tr>
              <th className="px-6 py-4 font-medium cursor-pointer hover:text-text-primary transition-colors" onClick={() => requestSort('repository')}>
                <div className="flex items-center gap-1">Repository <ArrowUpDown className="w-3 h-3" /></div>
              </th>
              <th className="px-6 py-4 font-medium cursor-pointer hover:text-text-primary transition-colors" onClick={() => requestSort('pull_request')}>
                <div className="flex items-center gap-1">Pull Request <ArrowUpDown className="w-3 h-3" /></div>
              </th>
              <th className="px-6 py-4 font-medium cursor-pointer hover:text-text-primary transition-colors" onClick={() => requestSort('status')}>
                <div className="flex items-center gap-1">Status <ArrowUpDown className="w-3 h-3" /></div>
              </th>
              <th className="px-6 py-4 font-medium cursor-pointer hover:text-text-primary transition-colors" onClick={() => requestSort('findings_count')}>
                <div className="flex items-center gap-1">Findings <ArrowUpDown className="w-3 h-3" /></div>
              </th>
              <th className="px-6 py-4 font-medium cursor-pointer hover:text-text-primary transition-colors" onClick={() => requestSort('created_at')}>
                <div className="flex items-center gap-1">Date <ArrowUpDown className="w-3 h-3" /></div>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {sortedScans.slice(0, 10).map((scan) => (
              <tr key={scan.id} className="hover:bg-bg-elevated/30 transition-colors">
                <td className="px-6 py-4 font-medium text-text-primary">{scan.repository}</td>
                <td className="px-6 py-4 text-text-secondary">#{scan.pull_request}</td>
                <td className="px-6 py-4">
                  {scan.status === 'clean' ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-accent-green/10 text-accent-green border border-accent-green/20">
                      <ShieldCheck className="w-3.5 h-3.5" /> Clean
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-accent-orange/10 text-accent-orange border border-accent-orange/20">
                      <ShieldAlert className="w-3.5 h-3.5" /> Findings
                    </span>
                  )}
                </td>
                <td className="px-6 py-4 font-mono text-text-secondary">{scan.findings_count}</td>
                <td className="px-6 py-4 text-text-secondary">
                  {new Date(scan.created_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
