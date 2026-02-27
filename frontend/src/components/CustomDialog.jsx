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
    const { dialog, closeDialog, handleConfirm, handleCancel } = useDialog();

    if (!dialog.isOpen) return null;

    const config = {
        success: {
            icon: <CheckCircle className="text-emerald-400" size={32} />,
            accent: 'bg-emerald-500/10',
            border: 'border-emerald-500/20',
            button: 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-500/20'
        },
        error: {
            icon: <AlertCircle className="text-rose-400" size={32} />,
            accent: 'bg-rose-500/10',
            border: 'border-rose-500/20',
            button: 'bg-rose-600 hover:bg-rose-500 shadow-rose-500/20'
        },
        warning: {
            icon: <AlertTriangle className="text-amber-400" size={32} />,
            accent: 'bg-amber-500/10',
            border: 'border-amber-500/20',
            button: 'bg-amber-600 hover:bg-amber-500 shadow-amber-500/20'
        },
        confirm: {
            icon: <HelpCircle className="text-[#3B82F6]" size={32} />,
            accent: 'bg-[#3B82F6]/10',
            border: 'border-[#3B82F6]/20',
            button: 'bg-[#3B82F6] hover:bg-[#2563EB]'
        },
        info: {
            icon: <Info className="text-blue-400" size={32} />,
            accent: 'bg-blue-500/10',
            border: 'border-blue-500/20',
            button: 'bg-blue-600 hover:bg-blue-500 shadow-blue-500/20'
        }
    };

    const style = config[dialog.type] || config.info;

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <div
                className={`w-full max-w-md bg-[#0F172A] border ${style.border} rounded-3xl overflow-hidden shadow-2xl animate-in fade-in zoom-in duration-300`}
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
                    <p className="text-slate-400 leading-relaxed">
                        {dialog.message}
                    </p>
                </div>

                {/* Actions */}
                <div className="px-8 pb-8 flex gap-3">
                    {dialog.type === 'confirm' ? (
                        <>
                            <button
                                onClick={handleCancel}
                                className="flex-1 py-3 px-4 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-sm font-bold uppercase tracking-wider transition-all"
                            >
                                {dialog.cancelText}
                            </button>
                            <button
                                onClick={handleConfirm}
                                className={`flex-1 py-3 px-4 ${style.button} text-white rounded-xl text-sm font-bold uppercase tracking-wider transition-all shadow-lg`}
                            >
                                {dialog.confirmText}
                            </button>
                        </>
                    ) : (
                        <button
                            onClick={closeDialog}
                            className={`w-full py-3 px-4 ${style.button} text-white rounded-xl text-sm font-bold uppercase tracking-wider transition-all shadow-lg`}
                        >
                            {dialog.confirmText || 'Close'}
                        </button>
                    )}
                </div>

                {/* Close Button X */}
                <button
                    onClick={closeDialog}
                    className="absolute top-4 right-4 text-slate-500 hover:text-white transition-colors p-1"
                >
                    <X size={18} />
                </button>
            </div>
        </div>
    );
};

export default CustomDialog;
