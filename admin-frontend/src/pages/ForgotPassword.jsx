import React, { useState } from 'react';
import { Shield, Mail, ArrowLeft, Loader2 } from 'lucide-react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { API_BASE_URL } from '../config';
import { useDialog } from '../context/DialogContext';

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);
    const { showDialog } = useDialog();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const formData = new FormData();
            formData.append('email', email);

            const res = await axios.post(`${API_BASE_URL}/forgot-password`, formData);

            showDialog({
                type: 'success',
                title: 'Request Sent',
                message: res.data.message
            });
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Request Failed',
                message: err.response?.data?.detail || 'Failed to generate reset link.'
            });
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-premium-bg flex items-center justify-center p-4">
            <div className="max-w-md w-full glass-card space-y-8 animate-in fade-in zoom-in duration-300">
                <div className="text-center">
                    <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-premium-primary/20 text-premium-primary mb-4">
                        <Shield size={32} />
                    </div>
                    <h2 className="text-3xl font-bold tracking-tight">Forgot Password</h2>
                    <p className="text-premium-secondary mt-2">Enter your admin email to reset access</p>
                </div>

                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    <div>
                        <label className="text-sm font-medium text-premium-secondary">Admin Email</label>
                        <div className="relative mt-1">
                            <Mail className="absolute left-3 top-3 text-premium-secondary" size={18} />
                            <input
                                type="email"
                                required
                                className="input-field w-full pl-10"
                                placeholder="admin@example.com"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="btn-primary w-full flex items-center justify-center gap-2 py-3 disabled:opacity-50"
                    >
                        {loading ? <Loader2 className="animate-spin" size={20} /> : <Mail size={20} />}
                        Send Reset Link
                    </button>

                    <div className="text-center">
                        <Link to="/login" className="inline-flex items-center gap-2 text-sm text-premium-secondary hover:text-white transition-colors">
                            <ArrowLeft size={16} />
                            Back to Login
                        </Link>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default ForgotPassword;
