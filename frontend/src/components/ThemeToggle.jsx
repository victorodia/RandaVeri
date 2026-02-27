import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

const ThemeToggle = () => {
    const { theme, toggleTheme } = useTheme();

    return (
        <button
            onClick={toggleTheme}
            className="p-2.5 rounded-xl bg-premium-surface border border-premium-border/50 text-premium-text hover:border-premium-primary/50 transition-all duration-300 shadow-lg hover:scale-110 active:scale-95 group focus:outline-none"
            aria-label="Toggle Theme"
        >
            <div className="relative w-5 h-5">
                <div className={`absolute inset-0 transition-all duration-500 transform ${theme === 'dark' ? 'opacity-100 rotate-0 scale-100' : 'opacity-0 rotate-90 scale-0'}`}>
                    <Moon size={20} className="text-blue-400 group-hover:text-blue-300" />
                </div>
                <div className={`absolute inset-0 transition-all duration-500 transform ${theme === 'light' ? 'opacity-100 rotate-0 scale-100' : 'opacity-0 -rotate-90 scale-0'}`}>
                    <Sun size={20} className="text-amber-500 group-hover:text-amber-400" />
                </div>
            </div>
        </button>
    );
};

export default ThemeToggle;
