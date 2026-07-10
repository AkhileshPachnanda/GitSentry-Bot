import { useDashboardStore, selectFindingsByType } from '../../stores/useDashboardStore';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';

export default function FindingTypesPieChart() {
  const data = useDashboardStore(selectFindingsByType);
  const total = data.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className="glass-panel p-5 rounded-2xl flex flex-col h-full">
      <h3 className="text-sm font-medium text-text-secondary uppercase tracking-wider mb-4">Finding Types</h3>
      <div className="flex-1 min-h-[200px] w-full">
        {total === 0 ? (
          <div className="w-full h-full flex items-center justify-center text-text-muted text-sm border border-dashed border-border rounded-lg">
            No findings recorded
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="45%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
                stroke="none"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border)', borderRadius: '8px', color: 'var(--text-primary)' }}
                itemStyle={{ color: 'var(--text-primary)' }}
              />
              <Legend 
                verticalAlign="bottom" 
                height={36} 
                iconType="circle"
                wrapperStyle={{ fontSize: '12px', color: 'var(--text-secondary)' }}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
