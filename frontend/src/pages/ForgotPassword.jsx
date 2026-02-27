import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useBranding } from '../context/BrandingContext';
import { Mail, ArrowLeft, Shield } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useDialog } from '../context/DialogContext';
import ThemeToggle from '../components/ThemeToggle';

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);
    const { forgotPassword } = useAuth();
    const { branding } = useBranding();
    const { showDialog } = useDialog();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const data = await forgotPassword(email);
            showDialog({
                type: 'success',
                title: 'Email Sent',
                message: data.message || 'If an account exists for this email, a reset link will be sent.',
            });
            setEmail('');
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Request Failed',
                message: err.response?.data?.detail || 'Failed to send reset link. Please try again.',
            });
        } finally {
            setLoading(false);
        }
    };

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
                    <h2 className="text-3xl font-bold tracking-tight">Forgot Password</h2>
                    <p className="text-premium-secondary mt-2">Enter your email to receive a reset link</p>
                </div>

                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    <div>
                        <label className="text-sm font-medium text-premium-secondary">Email Address</label>
                        <div className="relative mt-1">
                            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-premium-secondary" size={18} />
                            <input
                                type="email"
                                required
                                className="input-field w-full pl-10"
                                placeholder="name@example.com"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="btn-primary w-full flex items-center justify-center gap-2 py-3"
                    >
                        {loading ? 'Sending...' : 'Send Reset Link'}
                    </button>

                    <div className="text-center">
                        <Link
                            to="/login"
                            className="inline-flex items-center gap-2 text-sm text-premium-secondary hover:text-premium-primary transition-colors"
                        >
                            <ArrowLeft size={16} /> Back to Login
                        </Link>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default ForgotPassword;
