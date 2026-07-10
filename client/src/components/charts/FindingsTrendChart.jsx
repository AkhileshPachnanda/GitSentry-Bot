import { useDashboardStore } from '../../stores/useDashboardStore';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function FindingsTrendChart() {
  const scans = useDashboardStore(state => state.scans);
  
  // Aggregate findings by day (last 7 days)
  const today = new Date();
  today.setHours(0,0,0,0);
  
  const dataMap = new Map();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const dateStr = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    dataMap.set(dateStr, { name: dateStr, findings: 0 });
  }

  scans.forEach(scan => {
    const d = new Date(scan.created_at);
    d.setHours(0,0,0,0);
    const dateStr = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    if (dataMap.has(dateStr)) {
      const entry = dataMap.get(dateStr);
      entry.findings += (scan.findings_count || 0);
    }
  });

  const data = Array.from(dataMap.values());
  const hasData = data.some(d => d.findings > 0);

  return (
    <div className="glass-panel p-5 rounded-2xl flex flex-col h-full">
      <h3 className="text-sm font-medium text-text-secondary uppercase tracking-wider mb-6">Findings Trend (7d)</h3>
      <div className="flex-1 min-h-[200px] w-full">
        {!hasData ? (
          <div className="w-full h-full flex items-center justify-center text-text-muted text-sm border border-dashed border-border rounded-lg">
            Not enough data yet
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorFindings" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--accent-orange)" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="var(--accent-orange)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
              <YAxis stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip 
                contentStyle={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border)', borderRadius: '8px', color: 'var(--text-primary)' }}
                itemStyle={{ color: 'var(--accent-orange)' }}
              />
              <Area type="monotone" dataKey="findings" stroke="var(--accent-orange)" strokeWidth={2} fillOpacity={1} fill="url(#colorFindings)" />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
