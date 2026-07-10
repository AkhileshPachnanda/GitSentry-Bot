import { useMemo } from 'react';
import { useDashboardStore } from '../../stores/useDashboardStore';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function SeverityBreakdownChart() {
  const findings = useDashboardStore(state => state.findings);
  
  const data = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => {
      const sev = f.severity?.toLowerCase() || 'low';
      if (counts[sev] !== undefined) counts[sev]++;
    });
    return [
      { name: 'Critical', value: counts.critical, fill: 'var(--accent-red)' },
      { name: 'High', value: counts.high, fill: 'var(--accent-orange)' },
      { name: 'Medium', value: counts.medium, fill: 'var(--accent-yellow)' },
      { name: 'Low', value: counts.low, fill: 'var(--accent-green)' },
    ];
  }, [findings]);

  const total = data.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className="glass-panel p-5 rounded-2xl flex flex-col h-full">
      <h3 className="text-sm font-medium text-text-secondary uppercase tracking-wider mb-6">Severity Breakdown</h3>
      <div className="flex-1 min-h-[200px] w-full">
        {total === 0 ? (
          <div className="w-full h-full flex items-center justify-center text-text-muted text-sm border border-dashed border-border rounded-lg">
            No findings recorded
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart layout="vertical" data={data} margin={{ top: 0, right: 20, left: 10, bottom: 0 }}>
              <XAxis type="number" hide />
              <YAxis dataKey="name" type="category" stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} width={60} />
              <Tooltip 
                cursor={{ fill: 'var(--bg-elevated)', opacity: 0.4 }}
                contentStyle={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border)', borderRadius: '8px', color: 'var(--text-primary)' }}
                formatter={(value, name, props) => [value, 'Findings']}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={24}>
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
