import React, { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { CheckCircle2, AlertCircle, Loader2, Shield } from 'lucide-react';
import axios from 'axios';
import { API_BASE_URL } from '../config';

const VerifyEmail = () => {
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token');
    const [status, setStatus] = useState('loading'); // loading, success, error
    const [message, setMessage] = useState('');

    useEffect(() => {
        const verify = async () => {
            if (!token) {
                setStatus('error');
                setMessage('Verification token is missing.');
                return;
            }

            try {
                const formData = new FormData();
                formData.append('token', token);
                const res = await axios.post(API_BASE_URL + '/verify-email', formData);

                setStatus('success');
                setMessage(res.data.message);
            } catch (err) {
                setStatus('error');
                setMessage(err.response?.data?.detail || 'Verification failed. The link might be expired or invalid.');
            }
        };

        verify();
    }, [token]);

    return (
        <div className="min-h-screen bg-premium-bg flex items-center justify-center p-4 text-white">
            <div className="max-w-md w-full glass-card p-8 text-center space-y-6 animate-in fade-in zoom-in duration-300">
                <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-premium-primary/20 text-premium-primary mb-2">
                    <Shield size={32} />
                </div>

                <h2 className="text-3xl font-bold">Email Verification</h2>

                {status === 'loading' && (
                    <div className="py-8 space-y-4">
                        <Loader2 className="animate-spin text-premium-primary mx-auto" size={48} />
                        <p className="text-premium-secondary">Verifying your account security...</p>
                    </div>
                )}

                {status === 'success' && (
                    <div className="py-8 space-y-4">
                        <CheckCircle2 className="text-green-500 mx-auto" size={64} />
                        <h3 className="text-4xl font-black text-white uppercase tracking-tighter">Successful</h3>
                        <p className="text-xl text-premium-secondary font-medium">Please login to gain access</p>
                        <Link to="/" className="btn-primary block w-full py-3 mt-4">
                            Continue to Workspace
                        </Link>
                    </div>
                )}

                {status === 'error' && (
                    <div className="py-8 space-y-4">
                        <AlertCircle className="text-red-500 mx-auto" size={64} />
                        <p className="text-premium-secondary">{message}</p>
                        <Link to="/login" className="text-premium-primary hover:underline block pt-4">
                            Back to Login
                        </Link>
                    </div>
                )}

                <p className="text-[10px] text-white/20 uppercase tracking-widest pt-4">Randaframe Security Infrastructure</p>
            </div>
        </div>
    );
};

export default VerifyEmail;
