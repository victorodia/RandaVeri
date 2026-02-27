import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useBranding } from '../context/BrandingContext';
import { LogIn, UserPlus, Shield } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import PasswordInput from '../components/PasswordInput';
import { useDialog } from '../context/DialogContext';
import ThemeToggle from '../components/ThemeToggle';

const Login = () => {
    const [isLogin, setIsLogin] = useState(true);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const { login, user } = useAuth();
    const { branding } = useBranding();
    const { showDialog } = useDialog();
    const navigate = useNavigate();

    // Redirect if already logged in
    React.useEffect(() => {
        if (user) {
            if (user.is_password_change_required) {
                navigate('/change-password');
            } else {
                navigate('/dashboard');
            }
        }
    }, [user, navigate]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const data = await login(email, password, branding.orgSlug);
            if (data?.require_password_change) {
                navigate('/change-password');
            } else {
                navigate('/dashboard');
            }
        } catch (err) {
            const errorMsg = err.response?.data?.detail || 'Invalid credentials. Please try again.';
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
            {/* Theme Toggle in Corner */}
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
                    <h2 className="text-3xl font-bold tracking-tight">{branding.name}</h2>
                    <p className="text-premium-secondary mt-2">NIN Validation Aggregator</p>
                </div>

                <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
                    <div className="space-y-4">
                        <div>
                            <label className="text-sm font-medium text-premium-secondary">Username / Email</label>
                            <input
                                type="text"
                                required
                                className="input-field w-full mt-1"
                                placeholder="Enter your username"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
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
                            <div className="text-right mt-2">
                                <button
                                    type="button"
                                    onClick={() => navigate('/forgot-password')}
                                    className="text-xs text-premium-secondary hover:text-premium-primary transition-colors"
                                >
                                    Forgot Password?
                                </button>
                            </div>
                        </div>
                    </div>


                    <button type="submit" className="btn-primary w-full flex items-center justify-center gap-2 py-3">
                        <LogIn size={20} />
                        {isLogin ? 'Sign In' : 'Sign Up'}
                    </button>

                    <div className="pt-4 border-t border-premium-border">
                        <a
                            href="http://localhost:5173"
                            className="block w-full text-center text-sm text-premium-secondary hover:text-premium-primary transition-colors"
                        >
                            Back to Organisation Login
                        </a>
                    </div>
                </form>


            </div>
        </div>
    );
};

export default Login;
