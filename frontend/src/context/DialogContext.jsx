import React, { createContext, useContext, useState, useCallback } from 'react';

const DialogContext = createContext();

export const DialogProvider = ({ children }) => {
    const [dialog, setDialog] = useState({
        isOpen: false,
        type: 'info', // success, error, warning, confirm, info
        title: '',
        message: '',
        onConfirm: null,
        onCancel: null,
        confirmText: 'Confirm',
        cancelText: 'Cancel'
    });

    const showDialog = useCallback(({
        type = 'info',
        title,
        message,
        onConfirm,
        onCancel,
        confirmText = 'Confirm',
        cancelText = 'Cancel'
    }) => {
        setDialog({
            isOpen: true,
            type,
            title,
            message,
            onConfirm,
            onCancel,
            confirmText,
            cancelText
        });
    }, []);

    const closeDialog = useCallback(() => {
        setDialog(prev => ({ ...prev, isOpen: false }));
    }, []);

    const handleConfirm = () => {
        if (dialog.onConfirm) dialog.onConfirm();
        closeDialog();
    };

    const handleCancel = () => {
        if (dialog.onCancel) dialog.onCancel();
        closeDialog();
    };

    return (
        <DialogContext.Provider value={{ showDialog, closeDialog, dialog, handleConfirm, handleCancel }}>
            {children}
        </DialogContext.Provider>
    );
};

export const useDialog = () => {
    const context = useContext(DialogContext);
    if (!context) {
        throw new Error('useDialog must be used within a DialogProvider');
    }
    return context;
};
