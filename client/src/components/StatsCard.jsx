import { useEffect, useState } from 'react';

export default function StatsCard({ title, value, subtitle, icon: Icon, trend = null }) {
  const [displayValue, setDisplayValue] = useState(0);

  // Simple count-up animation
  useEffect(() => {
    if (typeof value !== 'number') {
      setDisplayValue(value);
      return;
    }
    let start = 0;
    const duration = 1000;
    const increment = Math.ceil(value / (duration / 16));
    const timer = setInterval(() => {
      start += increment;
      if (start >= value) {
        setDisplayValue(value);
        clearInterval(timer);
      } else {
        setDisplayValue(start);
      }
    }, 16);
    return () => clearInterval(timer);
  }, [value]);

  return (
    <div className="glass-panel p-5 rounded-2xl relative group overflow-hidden transition-all hover:border-accent-orange/50 hover:shadow-2xl hover:shadow-accent-orange/10">
      <div className="absolute -inset-1 bg-gradient-to-r from-accent-orange/20 to-accent-purple/20 opacity-0 group-hover:opacity-100 blur-xl transition-opacity duration-500 -z-10"></div>
      <div className="flex justify-between items-start">
        <div className="space-y-2">
          <p className="text-sm font-medium text-text-muted uppercase tracking-wider">{title}</p>
          <p className="text-3xl font-semibold text-text-primary tabular-nums">
            {displayValue}
          </p>
        </div>
        {Icon && (
          <div className="p-2 bg-bg-elevated rounded-lg text-accent-orange">
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>
      <div className="mt-4 flex items-center justify-between">
        <p className="text-sm text-text-secondary">{subtitle}</p>
        {trend !== null && (
          <span className={`text-xs font-medium px-2 py-1 rounded-full ${trend >= 0 ? 'bg-accent-green/10 text-accent-green' : 'bg-accent-red/10 text-accent-red'}`}>
            {trend >= 0 ? '+' : ''}{trend}%
          </span>
        )}
      </div>
    </div>
  );
}
