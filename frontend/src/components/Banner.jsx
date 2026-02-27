import React, { useEffect, useState } from 'react';
import { AlertCircle, CheckCircle, Info, X } from 'lucide-react';

const Banner = ({ message, type = 'error', onClose, duration = 5000 }) => {
    const [isVisible, setIsVisible] = useState(false);

    useEffect(() => {
        if (message) {
            setIsVisible(true);
            const timer = setTimeout(() => {
                handleClose();
            }, duration);
            return () => clearTimeout(timer);
        }
    }, [message, duration]);

    const handleClose = () => {
        setIsVisible(false);
        if (onClose) {
            setTimeout(onClose, 300); // Wait for animation
        }
    };

    if (!message) return null;

    const styles = {
        error: {
            bg: 'bg-red-500/10',
            border: 'border-red-500/20',
            text: 'text-red-400',
            icon: <AlertCircle className="text-red-400" size={20} />,
            gradient: 'from-red-500/20'
        },
        success: {
            bg: 'bg-emerald-500/10',
            border: 'border-emerald-500/20',
            text: 'text-emerald-400',
            icon: <CheckCircle className="text-emerald-400" size={20} />,
            gradient: 'from-emerald-500/20'
        },
        info: {
            bg: 'bg-blue-500/10',
            border: 'border-blue-500/20',
            text: 'text-blue-400',
            icon: <Info className="text-blue-400" size={20} />,
            gradient: 'from-blue-500/20'
        }
    };

    const currentStyle = styles[type] || styles.error;

    return (
        <div className={`fixed top-6 left-1/2 -translate-x-1/2 z-[100] w-full max-w-lg px-4 transition-all duration-500 ease-out ${isVisible ? 'translate-y-0 opacity-100' : '-translate-y-4 opacity-0 pointer-events-none'}`}>
            <div className={`${currentStyle.bg} backdrop-blur-md border ${currentStyle.border} p-4 rounded-2xl shadow-2xl relative overflow-hidden group`}>
                <div className={`absolute inset-0 bg-gradient-to-r ${currentStyle.gradient} to-transparent opacity-30`}></div>

                <div className="relative flex items-center gap-4">
                    <div className="flex-shrink-0 animate-in zoom-in duration-500">
                        {currentStyle.icon}
                    </div>

                    <div className="flex-grow">
                        <p className={`text-sm font-medium ${currentStyle.text}`}>{message}</p>
                    </div>

                    <button
                        onClick={handleClose}
                        className={`${currentStyle.text} opacity-50 hover:opacity-100 transition-opacity p-1 rounded-full hover:bg-white/5`}
                    >
                        <X size={16} />
                    </button>
                </div>

                {/* Progress bar */}
                <div className="absolute bottom-0 left-0 h-[2px] bg-current opacity-20 transition-all duration-[5000ms] linear w-0 group-[.visible]:w-full"></div>
            </div>
        </div>
    );
};

export default Banner;
