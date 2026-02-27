import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { LogIn, Shield, HelpCircle } from 'lucide-react';
import { useNavigate, Link } from 'react-router-dom';
import PasswordInput from '../components/PasswordInput';
import { useDialog } from '../context/DialogContext';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const { login } = useAuth();
    const { showDialog } = useDialog();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const data = await login(username, password);
            if (data?.require_password_change) {
                navigate('/change-password');
            } else {
                navigate('/');
            }
        } catch (err) {
            const errorMsg = err.response?.data?.detail || err.message || 'Unauthorized. Please use admin credentials.';
            showDialog({
                type: 'error',
                title: 'Access Denied',
                message: errorMsg,
                confirmText: 'Try Again'
            });
        }
    };

    return (
        <div className="min-h-screen bg-premium-bg flex items-center justify-center p-4">
            <div className="max-w-md w-full glass-card space-y-8">
                <div className="text-center">
                    <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-premium-primary/20 text-premium-primary mb-4">
                        <Shield size={32} />
                    </div>
                    <h2 className="text-3xl font-bold tracking-tight">Admin Portal</h2>
                    <p className="text-premium-secondary mt-2">Control Center Management</p>
                </div>

                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    <div className="space-y-4">
                        <div>
                            <label className="text-sm font-medium text-premium-secondary">Admin Username</label>
                            <input
                                type="text"
                                required
                                className="input-field w-full mt-1"
                                placeholder="Admin account"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                            />
                        </div>
                        <div>
                            <label className="text-sm font-medium text-premium-secondary">Password</label>
                            <PasswordInput
                                required
                                className="mt-1"
                                placeholder="••••••••"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </div>
                    </div>

                    <div className="flex items-center justify-end">
                        <Link to="/forgot-password" title="Forgot Password?" className="text-sm text-premium-secondary hover:text-premium-text transition-colors flex items-center gap-1">
                            <HelpCircle size={14} />
                            Forgot Password?
                        </Link>
                    </div>

                    <button type="submit" className="btn-primary w-full flex items-center justify-center gap-2 py-3">
                        <LogIn size={20} />
                        Access Dashboard
                    </button>
                </form>
            </div>
        </div>
    );
};

export default Login;
