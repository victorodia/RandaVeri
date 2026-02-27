import React from 'react';
import { useDialog } from '../context/DialogContext';
import {
    AlertCircle,
    CheckCircle,
    Info,
    AlertTriangle,
    X,
    HelpCircle
} from 'lucide-react';

const CustomDialog = () => {
    const { dialog, closeDialog, handleConfirm, handleCancel, setDialogPassword } = useDialog();

    if (!dialog.isOpen) return null;

    const config = {
        success: {
            icon: <CheckCircle className="text-emerald-400" size={32} />,
            accent: 'bg-emerald-500/10',
            border: 'border-emerald-500/20',
            button: 'btn-primary bg-emerald-600 hover:bg-emerald-500 shadow-emerald-900/20'
        },
        error: {
            icon: <AlertCircle className="text-rose-400" size={32} />,
            accent: 'bg-rose-500/10',
            border: 'border-rose-500/20',
            button: 'btn-primary bg-rose-600 hover:bg-rose-500 shadow-rose-900/20'
        },
        warning: {
            icon: <AlertTriangle className="text-amber-400" size={32} />,
            accent: 'bg-amber-500/10',
            border: 'border-amber-500/20',
            button: 'btn-primary bg-amber-600 hover:bg-amber-500 shadow-amber-900/20'
        },
        confirm: {
            icon: <HelpCircle className="text-premium-primary" size={32} />,
            accent: 'bg-premium-primary/10',
            border: 'border-premium-primary/20',
            button: 'btn-primary'
        },
        info: {
            icon: <Info className="text-blue-400" size={32} />,
            accent: 'bg-blue-500/10',
            border: 'border-blue-500/20',
            button: 'btn-primary bg-blue-600 hover:bg-blue-500 shadow-blue-900/20'
        }
    };

    const style = config[dialog.type] || config.info;

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm transition-all duration-300">
            <div
                className={`w-full max-w-md glass-card border ${style.border} overflow-hidden shadow-2xl scale-100 opacity-100 animate-in fade-in zoom-in duration-300`}
                onClick={e => e.stopPropagation()}
            >
                {/* Visual Accent Header */}
                <div className={`h-24 ${style.accent} flex items-center justify-center relative overflow-hidden`}>
                    <div className="absolute inset-0 opacity-20 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-white via-transparent to-transparent"></div>
                    <div className="p-3 bg-white/5 rounded-2xl backdrop-blur-md shadow-inner border border-white/10">
                        {style.icon}
                    </div>
                </div>

                {/* Content */}
                <div className="px-8 pt-8 pb-6 text-center">
                    <h3 className="text-xl font-bold text-white mb-2">{dialog.title}</h3>
                    <div className="text-premium-secondary leading-relaxed mb-6">
                        {dialog.message}
                    </div>

                    {dialog.isPasswordRequired && (
                        <div className="mt-4 text-left">
                            <label className="text-[10px] font-bold uppercase tracking-widest text-premium-secondary mb-1.5 block">
                                Confirm Admin Password
                            </label>
                            <input
                                type="password"
                                className="input-field w-full py-3 px-4 text-sm"
                                placeholder="Enter your password..."
                                value={dialog.password}
                                onChange={(e) => setDialogPassword(e.target.value)}
                                autoFocus
                            />
                        </div>
                    )}
                </div>

                {/* Actions */}
                <div className="px-8 pb-8 flex gap-3">
                    {dialog.type === 'confirm' ? (
                        <>
                            <button
                                onClick={handleCancel}
                                className="btn-secondary flex-1 py-3 text-sm font-bold uppercase tracking-wider"
                            >
                                {dialog.cancelText}
                            </button>
                            <button
                                onClick={handleConfirm}
                                className={`${style.button} flex-1 py-3 text-sm font-bold uppercase tracking-wider`}
                            >
                                {dialog.confirmText}
                            </button>
                        </>
                    ) : (
                        <button
                            onClick={closeDialog}
                            className={`${style.button} w-full py-3 text-sm font-bold uppercase tracking-wider`}
                        >
                            {dialog.confirmText || 'Close'}
                        </button>
                    )}
                </div>

                {/* Close Button X (optional) */}
                <button
                    onClick={closeDialog}
                    className="absolute top-4 right-4 text-premium-secondary hover:text-white transition-colors p-1"
                >
                    <X size={18} />
                </button>
            </div>
        </div>
    );
};

export default CustomDialog;
