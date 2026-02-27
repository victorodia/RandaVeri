
import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { API_BASE_URL } from '../config';
import { Shield, Lock, ArrowRight } from 'lucide-react';
import PasswordInput from '../components/PasswordInput';
import { useDialog } from '../context/DialogContext';

const ChangePassword = () => {
    const { logout } = useAuth();
    const navigate = useNavigate();
    const { showDialog } = useDialog();
    const [formData, setFormData] = useState({
        current_password: '',
        new_password: '',
        confirm_password: ''
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        if (formData.new_password !== formData.confirm_password) {
            setError("New passwords do not match");
            return;
        }

        if (formData.new_password.length < 6) {
            setError("Password must be at least 6 characters long");
            return;
        }

        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            const formPayload = new FormData();
            formPayload.append('current_password', formData.current_password);
            formPayload.append('new_password', formData.new_password);

            await axios.post(`${API_BASE_URL}/change-password`, formPayload, {
                headers: { Authorization: `Bearer ${token}` }
            });

            showDialog({
                type: 'success',
                title: 'Password Updated',
                message: 'Password changed successfully! Please login with your new password.'
            });
            logout();
            navigate('/login');
        } catch (err) {
            if (err.response && err.response.status === 401) {
                showDialog({
                    type: 'error',
                    title: 'Session Expired',
                    message: 'Session expired. Please login again.'
                });
                logout();
                navigate('/login');
            } else {
                setError(err.response?.data?.detail || "Failed to change password");
            }
        }
        setLoading(false);
    };

    return (
        <div className="min-h-screen bg-premium-bg flex items-center justify-center p-4 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-full premium-mesh opacity-30"></div>

            <div className="glass-card max-w-md w-full p-8 relative z-10 animate-in zoom-in duration-500">
                <div className="flex flex-col items-center mb-8">
                    <div className="h-16 w-16 bg-yellow-500/20 rounded-full flex items-center justify-center mb-4">
                        <Shield size={32} className="text-yellow-400" />
                    </div>
                    <h1 className="text-2xl font-bold">Security Update Required</h1>
                    <p className="text-premium-secondary text-center mt-2">
                        For your security, you must change your password before continuing.
                    </p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-4">
                    <div className="space-y-1">
                        <label className="text-xs font-bold text-premium-secondary uppercase">Current Password</label>
                        <div className="relative">
                            <Lock className="absolute left-3 top-3 text-premium-secondary z-10" size={18} />
                            <PasswordInput
                                className="pl-10"
                                required
                                value={formData.current_password}
                                onChange={e => setFormData({ ...formData, current_password: e.target.value })}
                            />
                        </div>
                    </div>

                    <div className="space-y-1">
                        <label className="text-xs font-bold text-premium-secondary uppercase">New Password</label>
                        <div className="relative">
                            <Lock className="absolute left-3 top-3 text-premium-secondary z-10" size={18} />
                            <PasswordInput
                                className="pl-10"
                                required
                                value={formData.new_password}
                                onChange={e => setFormData({ ...formData, new_password: e.target.value })}
                            />
                        </div>
                    </div>

                    <div className="space-y-1">
                        <label className="text-xs font-bold text-premium-secondary uppercase">Confirm New Password</label>
                        <div className="relative">
                            <Lock className="absolute left-3 top-3 text-premium-secondary z-10" size={18} />
                            <PasswordInput
                                className="pl-10"
                                required
                                value={formData.confirm_password}
                                onChange={e => setFormData({ ...formData, confirm_password: e.target.value })}
                            />
                        </div>
                    </div>

                    {error && (
                        <div className="bg-red-500/10 text-red-400 p-3 rounded text-sm text-center">
                            {error}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={loading}
                        className="btn-primary w-full py-3 flex items-center justify-center gap-2 group"
                    >
                        {loading ? 'Updating...' : (
                            <>Update Password <ArrowRight size={18} className="group-hover:translate-x-1 transition-transform" /></>
                        )}
                    </button>

                    <button
                        type="button"
                        onClick={logout}
                        className="w-full text-center text-sm text-premium-secondary hover:text-white transition-colors"
                    >
                        Cancel and Logout
                    </button>
                </form>
            </div>
        </div>
    );
};

export default ChangePassword;
