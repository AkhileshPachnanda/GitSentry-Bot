import ThemeToggle from './ThemeToggle';
import { Shield } from 'lucide-react';

export default function Layout({ children }) {
  return (
    <div className="min-h-screen flex flex-col">
      <header className="sticky top-0 z-50 w-full border-b border-border bg-bg-surface/80 backdrop-blur-md">
        <div className="container mx-auto px-4 md:px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2 text-accent-orange">
            <Shield className="w-6 h-6" />
            <span className="font-semibold text-lg text-text-primary tracking-tight">GitSentry</span>
          </div>
          <div className="flex items-center gap-4">
            <nav className="hidden md:flex gap-6 text-sm font-medium text-text-secondary">
              <a href="#" className="hover:text-text-primary transition-colors">Dashboard</a>
              <a href="#" className="hover:text-text-primary transition-colors">Repositories</a>
              <a href="#" className="hover:text-text-primary transition-colors">Settings</a>
            </nav>
            <div className="h-6 w-px bg-border hidden md:block"></div>
            <ThemeToggle />
          </div>
        </div>
      </header>
      <main className="flex-1 container mx-auto px-4 md:px-6 py-8">
        {children}
      </main>
    </div>
  );
}
