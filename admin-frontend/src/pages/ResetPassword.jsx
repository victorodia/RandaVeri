import React, { useState } from 'react';
import { Shield, Lock, Save, Loader2, CheckCircle2, AlertCircle } from 'lucide-react';
import { useSearchParams, useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { API_BASE_URL } from '../config';
import PasswordInput from '../components/PasswordInput';
import { useDialog } from '../context/DialogContext';

const ResetPassword = () => {
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token');
    const navigate = useNavigate();
    const { showDialog } = useDialog();

    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (password !== confirmPassword) {
            showDialog({
                type: 'error',
                title: 'Mismatch',
                message: 'Passwords do not match.'
            });
            return;
        }

        setLoading(true);
        try {
            const formData = new FormData();
            formData.append('token', token);
            formData.append('new_password', password);

            await axios.post(API_BASE_URL + '/reset-password', formData);

            setSuccess(true);
            showDialog({
                type: 'success',
                title: 'Password Updated',
                message: 'Your password has been reset successfully. You can now log in.'
            });
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Reset Failed',
                message: err.response?.data?.detail || 'Invalid or expired reset token.'
            });
        } finally {
            setLoading(false);
        }
    };

    if (!token) {
        return (
            <div className="min-h-screen bg-premium-bg flex items-center justify-center p-4">
                <div className="max-w-md w-full glass-card p-8 text-center space-y-4">
                    <AlertCircle className="text-red-500 mx-auto" size={48} />
                    <h2 className="text-2xl font-bold text-white">Invalid Request</h2>
                    <p className="text-premium-secondary">No reset token provided. Please request a new link.</p>
                    <Link to="/forgot-password" title="Request New Link" className="btn-primary inline-block py-2 px-6">Forgot Password</Link>
                </div>
            </div>
        );
    }

    if (success) {
        return (
            <div className="min-h-screen bg-premium-bg flex items-center justify-center p-4">
                <div className="max-w-md w-full glass-card p-8 text-center space-y-6">
                    <CheckCircle2 className="text-premium-accent mx-auto" size={64} />
                    <h2 className="text-2xl font-bold text-white">Reset Complete</h2>
                    <p className="text-premium-secondary">Security credentials updated. You're ready to go.</p>
                    <Link to="/login" title="Login Now" className="btn-primary block w-full py-3">Login to Dashboard</Link>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-premium-bg flex items-center justify-center p-4">
            <div className="max-w-md w-full glass-card space-y-8 animate-in fade-in zoom-in duration-300">
                <div className="text-center">
                    <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-premium-primary/20 text-premium-primary mb-4">
                        <Lock size={32} />
                    </div>
                    <h2 className="text-3xl font-bold tracking-tight">Set New Password</h2>
                    <p className="text-premium-secondary mt-2">Almost there! Choose a secure password</p>
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

                    <button
                        type="submit"
                        disabled={loading}
                        className="btn-primary w-full flex items-center justify-center gap-2 py-3 disabled:opacity-50"
                    >
                        {loading ? <Loader2 className="animate-spin" size={20} /> : <Save size={20} />}
                        Update Password
                    </button>
                </form>
            </div>
        </div>
    );
};

export default ResetPassword;
