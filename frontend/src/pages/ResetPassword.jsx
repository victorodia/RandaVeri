import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useBranding } from '../context/BrandingContext';
import { Lock, Save, Shield, CheckCircle2, AlertCircle } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import PasswordInput from '../components/PasswordInput';
import { useDialog } from '../context/DialogContext';
import ThemeToggle from '../components/ThemeToggle';

const ResetPassword = () => {
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token');
    const { resetPassword } = useAuth();
    const { branding } = useBranding();
    const { showDialog } = useDialog();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (password !== confirmPassword) {
            showDialog({
                type: 'error',
                title: 'Validation Error',
                message: 'Passwords do not match.',
            });
            return;
        }

        if (!token) {
            showDialog({
                type: 'error',
                title: 'Invalid Request',
                message: 'Reset token is missing.',
            });
            return;
        }

        setLoading(true);
        try {
            await resetPassword(token, password);
            showDialog({
                type: 'success',
                title: 'Password Reset Successful',
                message: 'Your password has been updated. You can now log in with your new password.',
            });
            navigate('/login');
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Reset Failed',
                message: err.response?.data?.detail || 'Failed to reset password. The link may have expired.',
            });
        } finally {
            setLoading(false);
        }
    };

    if (!token) {
        return (
            <div className="min-h-screen bg-premium-bg flex items-center justify-center p-4">
                <div className="max-w-md w-full glass-card text-center space-y-6">
                    <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-status-red/10 text-status-red mb-4">
                        <AlertCircle size={32} />
                    </div>
                    <h2 className="text-2xl font-bold">Invalid Reset Link</h2>
                    <p className="text-premium-secondary">This password reset link is invalid or has expired.</p>
                    <button onClick={() => navigate('/login')} className="btn-primary w-full py-3">
                        Back to Login
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-premium-bg flex items-center justify-center p-4">
            <div className="fixed top-6 right-6 z-50">
                <ThemeToggle />
            </div>
            <div className="max-w-md w-full glass-card space-y-8">
                <div className="text-center">
                    {branding.logoUrl ? (
                        <div className="h-20 w-auto mx-auto mb-4">
                            <img
                                src={branding.logoUrl}
                                alt={branding.name}
                                className="h-full w-full object-contain"
                            />
                        </div>
                    ) : (
                        <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-premium-primary/20 text-premium-primary mb-4">
                            <Shield size={32} />
                        </div>
                    )}
                    <h2 className="text-3xl font-bold tracking-tight">Reset Password</h2>
                    <p className="text-premium-secondary mt-2">Enter your new password below</p>
                </div>

                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    <div className="space-y-4">
                        <div>
                            <label className="text-sm font-medium text-premium-secondary">New Password</label>
                            <PasswordInput
                                required
                                className="mt-1"
                                placeholder="••••••••"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </div>
                        <div>
                            <label className="text-sm font-medium text-premium-secondary">Confirm New Password</label>
                            <PasswordInput
                                required
                                className="mt-1"
                                placeholder="••••••••"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                            />
                        </div>
                    </div>

                    <div className="space-y-2">
                        <div className="flex items-center gap-2 text-xs text-premium-secondary">
                            <CheckCircle2 size={12} className={password.length >= 8 ? 'text-status-emerald' : ''} />
                            <span>At least 8 characters</span>
                        </div>
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="btn-primary w-full flex items-center justify-center gap-2 py-3"
                    >
                        {loading ? 'Updating...' : 'Set New Password'}
                    </button>
                </form>
            </div>
        </div>
    );
};

export default ResetPassword;
