import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import {
    Wallet, Activity, Search, LogOut, LayoutDashboard, History,
    FileText, Palette, Shield, Users, CreditCard,
    CheckCircle, XCircle, Lock, Zap, ArrowUpCircle, TrendingUp, TrendingDown, Filter, Plus,
    Printer, Download, Edit2, ChevronDown, ChevronUp
} from 'lucide-react';
import html2canvas from 'html2canvas';
import VerificationSlip from '../components/VerificationSlip';
import { useBranding } from '../context/BrandingContext';
import { useDialog } from '../context/DialogContext';
import axios from 'axios';
import { API_BASE_URL } from '../config';
import { Link, useNavigate } from 'react-router-dom';
import PasswordInput from '../components/PasswordInput';
import ThemeToggle from '../components/ThemeToggle';

const Dashboard = () => {
    const { user, logout, fetchUser } = useAuth();
    const { branding, updateBranding } = useBranding();
    const navigate = useNavigate();
    const [nin, setNin] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleLogout = async () => {
        await logout();
        window.location.href = '/';
    };

    console.log("Dashboard User:", user);

    // Determine initial tab based on permissions
    const getInitialTab = () => {
        if (user?.role === 'admin' || user?.role?.includes('IDENTITY')) return 'verify';
        if (user?.role?.includes('WALLET')) return 'history';
        if (user?.role?.includes('org_admin')) return 'team';
        return 'verify';
    };

    const [activeTab, setActiveTab] = useState(getInitialTab());
    const [subTab, setSubTab] = useState('form'); // 'form' or 'logs'
    const [transactions, setTransactions] = useState([]);
    const [orgUsers, setOrgUsers] = useState([]);
    const [newUser, setNewUser] = useState({ username: '', email: '', telephone: '', password: '', role: 'user' });
    const [createLoading, setCreateLoading] = useState(false);
    const [isEditModalOpen, setIsEditModalOpen] = useState(false);
    const [editingUser, setEditingUser] = useState(null);
    const [printableResult, setPrintableResult] = useState(null);
    const [historyPage, setHistoryPage] = useState(1);
    const [teamPage, setTeamPage] = useState(1);
    const [auditPage, setAuditPage] = useState(1);
    const [verifyLogsPage, setVerifyLogsPage] = useState(1);
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');
    const [sortOrder, setSortOrder] = useState('desc'); // 'asc' or 'desc'
    const ITEMS_PER_PAGE = 10;
    const { showDialog, setDialogPassword } = useDialog();
    const slipRef = React.useRef(null);

    const showSuccess = (msg) => {
        showDialog({
            type: 'success',
            title: 'Success',
            message: msg
        });
    };

    // Subscription & Payment Logic
    const [paymentProcessing, setPaymentProcessing] = useState(false);
    const [showTopupModal, setShowTopupModal] = useState(false);
    const [showPaymentModal, setShowPaymentModal] = useState(false);
    const [topupUnits, setTopupUnits] = useState(100);
    const [topupProcessing, setTopupProcessing] = useState(false);

    const handleTopup = async (e) => {
        e.preventDefault();
        setTopupProcessing(true);
        try {
            const token = localStorage.getItem('token');
            const formData = new FormData();
            formData.append('units', topupUnits);
            formData.append('payment_method', 'card');

            // Simulate delay
            await new Promise(r => setTimeout(r, 1500));

            await axios.post('http://localhost:8000/topup', formData, {
                headers: { Authorization: `Bearer ${token}` }
            });

            await fetchUser(); // Refresh units
            setShowTopupModal(false);
            showSuccess(`Successfully purchased ${topupUnits} units!`);
            if (activeTab === 'history') fetchHistory();
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Purchase Failed',
                message: err.response?.data?.detail || err.message
            });
            setTopupProcessing(false);
        };
    };

    const handleSubscribe = async () => {
        setPaymentProcessing(true);
        try {
            const token = localStorage.getItem('token');
            // Simulate payment delay
            await new Promise(r => setTimeout(r, 2000));

            const formData = new FormData();
            formData.append('plan_id', 'yearly_license');
            formData.append('payment_method', 'card');

            await axios.post('http://localhost:8000/subscribe', formData, {
                headers: { Authorization: `Bearer ${token}` }
            });

            await fetchUser(); // Refresh org status
            setShowPaymentModal(false);
            showSuccess("Subscription activated! Welcome to the premium tier.");
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Subscription Failed',
                message: err.response?.data?.detail || err.message
            });
        }
        setPaymentProcessing(false);
    };

    const isSubscriptionActive = user?.organisation?.subscription_status === 'active';
    const isExpired = user?.organisation?.subscription_expiry && new Date(user.organisation.subscription_expiry) < new Date();

    // Exempt Super Admin and Default Org from lock screen
    const isSuperAdmin = user?.role === 'admin';
    const isDefaultOrg = user?.organisation?.slug === 'default';
    const showLockScreen = !isSuperAdmin && !isDefaultOrg && (!isSubscriptionActive || isExpired) && user?.organisation;
    const isOrgAdmin = user?.role?.includes('org_admin');


    const handleUpdateUserRole = async () => {
        try {
            const token = localStorage.getItem('token');
            await axios.put(`http://localhost:8000/org/users/${editingUser.id}`, {
                role: editingUser.role
            }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            showSuccess(`Role for ${editingUser.username} updated to ${editingUser.role}`);
            setIsEditModalOpen(false);
            fetchOrgUsers();
        } catch (err) {
            console.error(err);
            showDialog({
                type: 'error',
                title: 'Update Failed',
                message: 'Failed to update user role.'
            });
        }
    };

    const getFilteredData = (data) => {
        let filtered = [...data];

        if (startDate) {
            const start = new Date(startDate);
            start.setHours(0, 0, 0, 0);
            filtered = filtered.filter(item => new Date(item.timestamp) >= start);
        }

        if (endDate) {
            const end = new Date(endDate);
            end.setHours(23, 59, 59, 999);
            filtered = filtered.filter(item => new Date(item.timestamp) <= end);
        }

        filtered.sort((a, b) => {
            const dateA = new Date(a.timestamp);
            const dateB = new Date(b.timestamp);
            return sortOrder === 'desc' ? dateB - dateA : dateA - dateB;
        });

        return filtered;
    };

    const clearDateFilters = () => {
        setStartDate('');
        setEndDate('');
        setSortOrder('desc');
        setHistoryPage(1);
        setAuditPage(1);
        setVerifyLogsPage(1);
    };

    const FilterBar = () => (
        <div className="flex flex-wrap items-center gap-4 mb-6 p-4 bg-premium-overlay/30 rounded-xl border border-premium-border/50">
            <div className="flex items-center gap-3">
                <Filter size={14} className="text-premium-primary" />
                <span className="text-[10px] font-bold uppercase tracking-widest text-premium-secondary">Filter by Date</span>
            </div>
            <div className="flex items-center gap-2">
                <input
                    type="date"
                    value={startDate}
                    onChange={(e) => { setStartDate(e.target.value); setHistoryPage(1); setAuditPage(1); setVerifyLogsPage(1); }}
                    className="bg-premium-bg border border-premium-border rounded-lg px-3 py-1 text-sm focus:border-premium-primary outline-none transition-colors"
                />
                <span className="text-premium-secondary">→</span>
                <input
                    type="date"
                    value={endDate}
                    onChange={(e) => { setEndDate(e.target.value); setHistoryPage(1); setAuditPage(1); setVerifyLogsPage(1); }}
                    className="bg-premium-bg border border-premium-border rounded-lg px-3 py-1 text-sm focus:border-premium-primary outline-none transition-colors"
                />
            </div>
            <button
                onClick={() => setSortOrder(p => p === 'desc' ? 'asc' : 'desc')}
                className="flex items-center gap-2 px-3 py-1 bg-premium-bg border border-premium-border rounded-lg text-xs font-bold uppercase tracking-wider hover:text-premium-primary transition-all"
            >
                {sortOrder === 'desc' ? <TrendingDown size={14} /> : <TrendingUp size={14} />}
                {sortOrder === 'desc' ? 'Newest' : 'Oldest'}
            </button>
            {(startDate || endDate) && (
                <button
                    onClick={clearDateFilters}
                    className="text-[10px] font-bold uppercase tracking-widest text-premium-secondary hover:text-premium-primary transition-colors"
                >
                    Clear
                </button>
            )}
        </div>
    );

    const handleToggleUserSuspension = async (user) => {
        const action = user.is_active ? 'Suspend' : 'Activate';
        showDialog({
            type: 'confirm',
            title: `${action} Team Member`,
            message: `Are you sure you want to ${action.toLowerCase()} ${user.username}?`,
            confirmText: `Confirm ${action}`,
            isPasswordRequired: true,
            onConfirm: async (password) => {
                if (!password) {
                    showDialog({ type: 'error', title: 'Password Required', message: 'Your password is required to confirm this action.' });
                    return;
                }
                try {
                    const token = localStorage.getItem('token');
                    const res = await axios.post(`http://localhost:8000/org/users/${user.id}/toggle-suspension`, { password }, {
                        headers: { Authorization: `Bearer ${token}` }
                    });
                    showSuccess(res.data.message);
                    fetchOrgUsers();
                } catch (err) {
                    showDialog({
                        type: 'error',
                        title: 'Action Failed',
                        message: err.response?.data?.detail || "Action failed"
                    });
                }
            }
        });
    };

    const handleVerify = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            const response = await axios.post(`http://localhost:8000/verify-nin?nin=${nin}`, {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setResult(response.data);
            setPrintableResult(response.data);
            await fetchUser(); // Refresh wallet
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Verification Failed',
                message: err.response?.data?.detail || 'Verification failed'
            });
        }
        setLoading(false);
    };

    const handlePrint = (txResult) => {
        setPrintableResult(txResult);
        setTimeout(() => {
            window.print();
        }, 100);
    };

    const handleDownload = async (txResult) => {
        setPrintableResult(txResult);
        // Small delay to ensure the off-screen component is rendered with the new data
        setTimeout(async () => {
            if (slipRef.current) {
                try {
                    const canvas = await html2canvas(slipRef.current, {
                        scale: 2, // High-quality export
                        useCORS: true,
                        allowTaint: true,
                        backgroundColor: '#ffffff',
                        logging: false
                    });

                    const dataUrl = canvas.toDataURL('image/png');
                    const link = document.createElement('a');
                    link.download = `verification-slip-${txResult.data?.transaction_id || Date.now()}.png`;
                    link.href = dataUrl;
                    link.click();
                } catch (err) {
                    console.error('Download failed', err);
                    showDialog({
                        type: 'error',
                        title: 'Download Failed',
                        message: 'Download failed. Please try printing to PDF as a fallback.'
                    });
                }
            }
        }, 500); // Increased delay for security
    };

    const fetchHistory = async () => {
        const token = localStorage.getItem('token');
        const response = await axios.get('http://localhost:8000/transactions', {
            headers: { Authorization: `Bearer ${token}` }
        });
        setTransactions(response.data);
    };

    const fetchOrgUsers = async () => {
        const token = localStorage.getItem('token');
        try {
            const response = await axios.get('http://localhost:8000/org/users', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setOrgUsers(response.data);
        } catch (error) {
            console.error("Failed to fetch org users", error);
        }
    };

    const handleCreateUser = async (e) => {
        e.preventDefault();
        setCreateLoading(true);
        const token = localStorage.getItem('token');
        try {
            await axios.post('http://localhost:8000/org/users', newUser, {
                headers: { Authorization: `Bearer ${token}` }
            });
            showDialog({
                type: 'success',
                title: 'User Created',
                message: `Verification email has been sent to ${newUser.email}, and the user needs to be verified.`
            });
            setNewUser({ username: '', email: '', telephone: '', password: '', role: 'user' });
            fetchOrgUsers();
        } catch (error) {
            showDialog({
                type: 'error',
                title: 'Creation Failed',
                message: error.response?.data?.detail || 'Failed to create user'
            });
        }
        setCreateLoading(false);
    };
    useEffect(() => {
        if (activeTab === 'history' || activeTab === 'audit' || (activeTab === 'verify' && subTab === 'logs')) fetchHistory();
        if (activeTab === 'team') fetchOrgUsers();
    }, [activeTab, subTab]);

    useEffect(() => {
        if (user) {
            setActiveTab(getInitialTab());
        }
    }, [user]);

    return (
        <div className="flex min-h-screen bg-premium-bg">
            {/* Topup Modal */}
            {showTopupModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
                    <div className="glass-card max-w-md w-full animate-in fade-in zoom-in-95">
                        <div className="flex justify-between items-center mb-6">
                            <h2 className="text-2xl font-bold flex items-center gap-2">
                                <Zap className="text-premium-primary" />
                                Top-up Units
                            </h2>
                            <button onClick={() => setShowTopupModal(false)} className="text-premium-secondary hover:text-premium-text">✕</button>
                        </div>

                        <div className="mb-6 p-4 bg-premium-primary/10 border border-premium-primary/20 rounded-lg space-y-2">
                            <div className="flex justify-between items-center">
                                <span className="text-sm text-premium-secondary uppercase font-bold">Tier</span>
                                <span className="font-bold text-premium-primary">{user?.organisation?.tier_name}</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-sm text-premium-secondary uppercase font-bold">Cost per unit</span>
                                <span className="font-bold">₦{user?.organisation?.custom_unit_cost || user?.organisation?.tier_default_cost}</span>
                            </div>
                        </div>

                        <form onSubmit={handleTopup} className="space-y-6">
                            <div>
                                <label className="text-xs font-bold text-premium-secondary uppercase mb-3 block">Select Amount (Multiples of 100)</label>
                                <div className="grid grid-cols-2 gap-3 mb-4">
                                    {[100, 200, 500, 1000].map(amt => (
                                        <button
                                            key={amt}
                                            type="button"
                                            onClick={() => setTopupUnits(amt)}
                                            className={`py-3 rounded-lg border font-bold transition-all ${topupUnits === amt ? 'bg-premium-primary border-premium-primary text-white shadow-lg' : 'bg-premium-overlay border-premium-border text-premium-secondary hover:border-premium-primary/50'}`}
                                        >
                                            {amt} Units
                                        </button>
                                    ))}
                                </div>
                                <div className="flex justify-between items-center p-4 bg-premium-overlay rounded-xl border border-premium-border">
                                    <span className="text-premium-secondary">Total Price</span>
                                    <span className="text-2xl font-bold text-premium-text">
                                        ₦{(topupUnits * (user?.organisation?.custom_unit_cost || user?.organisation?.tier_default_cost || 1.0)).toLocaleString()}
                                    </span>
                                </div>
                            </div>

                            <div className="space-y-4 pt-2">
                                <h4 className="text-[10px] text-premium-secondary uppercase font-bold tracking-widest text-center">Payment Simulation</h4>
                                <button
                                    type="submit"
                                    disabled={topupProcessing}
                                    className="btn-primary w-full py-4 flex items-center justify-center gap-2 text-lg font-bold shadow-xl shadow-premium-primary/20"
                                >
                                    {topupProcessing ? (
                                        <div className="h-5 w-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                    ) : (
                                        <>
                                            <CreditCard size={20} /> Checkout & Add Units
                                        </>
                                    )}
                                </button>
                                <p className="text-center text-[10px] text-premium-secondary flex items-center justify-center gap-1">
                                    <Shield size={10} /> Secure Sandbox Gateway
                                </p>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Payment Modal for Yearly Subscription */}
            {showPaymentModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
                    <div className="glass-card max-w-md w-full animate-in fade-in zoom-in-95">
                        <div className="flex justify-between items-center mb-6">
                            <h2 className="text-2xl font-bold flex items-center gap-2">
                                <CreditCard className="text-premium-primary" />
                                Yearly Subscription
                            </h2>
                            <button onClick={() => setShowPaymentModal(false)} className="text-premium-secondary hover:text-premium-text">✕</button>
                        </div>

                        <div className="space-y-6">
                            <div className="p-4 bg-premium-overlay rounded-xl border border-premium-border">
                                <div className="flex justify-between items-center mb-2">
                                    <span className="text-premium-secondary">Plan</span>
                                    <span className="font-bold">Yearly Platform License</span>
                                </div>
                                <div className="flex justify-between items-center text-xl font-bold text-premium-text">
                                    <span>Subscription Price</span>
                                    <span>₦{user?.organisation?.subscription_price?.toLocaleString() || '500,000'}</span>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <h4 className="text-[10px] text-premium-secondary uppercase font-bold tracking-widest text-center">Secure Payment Simulation</h4>
                                <button
                                    onClick={handleSubscribe}
                                    disabled={paymentProcessing}
                                    className="btn-primary w-full py-4 flex items-center justify-center gap-2 text-lg font-bold shadow-xl shadow-premium-primary/20"
                                >
                                    {paymentProcessing ? (
                                        <div className="h-5 w-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                    ) : (
                                        <>
                                            <Shield size={20} /> Authorize & Pay ₦{user?.organisation?.subscription_price?.toLocaleString() || '500,000'}
                                        </>
                                    )}
                                </button>
                                <p className="text-center text-[10px] text-premium-secondary flex items-center justify-center gap-1">
                                    <Lock size={10} /> Encrypted Gateway Entry
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {showLockScreen ? (
                <div className="w-full flex flex-col items-center justify-center p-4 text-center space-y-8 max-w-2xl mx-auto animate-in fade-in slide-in-from-bottom-8">
                    <div className="h-24 w-24 rounded-full bg-premium-primary/20 flex items-center justify-center mb-4 ring-8 ring-premium-primary/5">
                        <Lock size={48} className="text-premium-primary" />
                    </div>
                    <div>
                        <h1 className="text-4xl font-bold mb-2">
                            {isExpired ? "Subscription Expired" : "Yearly Access Required"}
                        </h1>
                        <p className="text-xl text-premium-secondary">
                            Your organisation <span className="text-premium-text font-bold">{user.organisation?.name}</span> {isExpired ? "subscription has ended" : "needs an active yearly subscription"} to enable services.
                        </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full text-left">
                        <div className="glass-card p-6 space-y-3 border-t-2 border-t-premium-primary">
                            <div className="h-10 w-10 rounded-lg bg-status-emerald/10 flex items-center justify-center">
                                <CheckCircle className="text-status-emerald" size={24} />
                            </div>
                            <h3 className="font-bold text-lg">Platform Access</h3>
                            <p className="text-sm text-premium-secondary leading-relaxed">Yearly license for all team members to access the application suite.</p>
                        </div>
                        <div className="glass-card p-6 space-y-3">
                            <div className="h-10 w-10 rounded-lg bg-status-blue/10 flex items-center justify-center">
                                <Wallet className="text-status-blue" size={24} />
                            </div>
                            <h3 className="font-bold text-lg">Shared Wallet</h3>
                            <p className="text-sm text-premium-secondary leading-relaxed">Centrally managed units for seamless organisational operations.</p>
                        </div>
                        <div className="glass-card p-6 space-y-3">
                            <div className="h-10 w-10 rounded-lg bg-premium-accent/10 flex items-center justify-center">
                                <Shield className="text-premium-accent" size={24} />
                            </div>
                            <h3 className="font-bold text-lg">Identity Verification</h3>
                            <p className="text-sm text-premium-secondary leading-relaxed">Unlimited access to the NIN validation portal and secure API logs.</p>
                        </div>
                    </div>

                    <div className="flex flex-col items-center gap-6 w-full max-w-md">
                        {isOrgAdmin ? (
                            <>
                                <button onClick={() => setShowPaymentModal(true)} className="btn-primary w-full py-4 text-lg font-bold shadow-2xl shadow-premium-primary/40 flex items-center justify-center gap-2">
                                    <CreditCard size={20} />
                                    {isExpired ? `Renew Yearly Access (₦${user?.organisation?.subscription_price?.toLocaleString() || '500,000'})` : `Activate Yearly Access (₦${user?.organisation?.subscription_price?.toLocaleString() || '500,000'})`}
                                </button>
                                <p className="text-sm text-premium-secondary">As an **Organisation Admin**, you can authorize this payment.</p>
                            </>
                        ) : (
                            <div className="bg-premium-overlay border border-white/10 rounded-2xl p-6 w-full">
                                <p className="text-premium-secondary italic mb-2 font-medium">Wait for your Admin...</p>
                                <p className="text-sm text-premium-secondary">
                                    Only users with <span className="text-premium-text font-bold">Organisation Admin</span> privileges can subscribe. Please contact your administrator to unlock the platform.
                                </p>
                            </div>
                        )}
                        <button onClick={handleLogout} className="text-premium-secondary hover:text-premium-text flex items-center gap-2 transition-all">
                            <LogOut size={16} /> Sign out and try another account
                        </button>
                    </div>
                </div>
            ) : (
                <>
                    {/* Sidebar */}
                    <div className="w-64 border-r border-premium-border bg-premium-surface p-6 flex flex-col">
                        <div className="flex items-center gap-3 mb-10">
                            {branding.logoUrl ? (
                                <div className="h-24 w-24 flex items-center justify-center">
                                    <img
                                        src={branding.logoUrl}
                                        alt={branding.name}
                                        className="h-full w-full object-contain"
                                    />
                                </div>
                            ) : (
                                <div className="h-24 w-24 premium-gradient rounded-lg flex items-center justify-center">
                                    <span className="font-bold text-4xl">{branding.logoText}</span>
                                </div>
                            )}
                            <span className="font-bold text-xl tracking-tight">{branding.name}</span>
                        </div>

                        <nav className="flex-1 space-y-2">
                            {(user?.role?.includes('admin') || user?.role?.includes('IDENTITY')) && (
                                <NavItem icon={<LayoutDashboard size={20} />} label="Verification" active={activeTab === 'verify'} onClick={() => setActiveTab('verify')} />
                            )}
                            {(user?.role?.includes('admin') || user?.role?.includes('WALLET')) && (
                                <NavItem icon={<History size={20} />} label="History" active={activeTab === 'history'} onClick={() => setActiveTab('history')} />
                            )}
                            {(user?.role?.includes('org_admin')) && (
                                <NavItem icon={<Users size={20} />} label="Team" active={activeTab === 'team'} onClick={() => setActiveTab('team')} />
                            )}
                            <NavItem icon={<FileText size={20} />} label="Audit Logs" active={activeTab === 'audit'} onClick={() => setActiveTab('audit')} />
                            {/* ONLY Super Admin sees Control Center */}
                            {user?.role === 'admin' && (
                                <Link to="/admin" className="w-full flex items-center gap-3 p-3 rounded-lg text-premium-accent hover:text-premium-text hover:bg-premium-overlay transition-all mt-4 border border-premium-accent/20">
                                    <Shield size={20} />
                                    <span className="font-medium">Control Center</span>
                                </Link>
                            )}
                        </nav>

                        <button onClick={handleLogout} className="mt-auto flex items-center gap-3 text-premium-secondary hover:text-premium-text p-2">
                            <LogOut size={20} />
                            <span>Logout</span>
                        </button>
                    </div>

                    {/* Main Content */}
                    <div className="flex-1 p-8 overflow-y-auto">
                        <header className="flex justify-between items-center mb-10">
                            <div>
                                <h1 className="text-2xl font-bold">Welcome back, {user?.username}</h1>
                                <p className="text-premium-secondary">Manage your NIN validations and wallet balance.</p>
                            </div>

                            <div className="flex gap-4">
                                <div className="glass-card flex items-center gap-4 py-3 px-6">
                                    <div className="h-10 w-10 rounded-full bg-premium-primary/20 text-premium-primary flex items-center justify-center">
                                        <Wallet size={20} />
                                    </div>
                                    <div>
                                        <p className="text-xs text-premium-secondary uppercase">Organisation Balance</p>
                                        <div className="flex items-center gap-3">
                                            <p className="text-lg font-bold">{user?.units} Units</p>
                                            {isOrgAdmin && (
                                                <button
                                                    onClick={() => setShowTopupModal(true)}
                                                    className="p-1.5 bg-premium-primary/20 text-premium-primary hover:bg-premium-primary hover:text-premium-text rounded-lg transition-all"
                                                    title="Top-up Units"
                                                >
                                                    <Plus size={16} />
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                </div>


                                <ThemeToggle />
                            </div>
                        </header>

                        {activeTab === 'verify' && (user?.role?.includes('admin') || user?.role?.includes('IDENTITY')) && (
                            <div className="space-y-6">
                                {/* Sub-tabs for Verification */}
                                <div className="flex gap-1 bg-premium-overlay p-1 rounded-xl w-fit mb-8">
                                    <button
                                        onClick={() => setSubTab('form')}
                                        className={`px-6 py-2 rounded-lg text-sm font-bold transition-all ${subTab === 'form' ? 'bg-premium-primary text-white shadow-lg' : 'text-premium-secondary hover:text-premium-text'}`}
                                    >
                                        Verify Now
                                    </button>
                                    <button
                                        onClick={() => setSubTab('logs')}
                                        className={`px-6 py-2 rounded-lg text-sm font-bold transition-all ${subTab === 'logs' ? 'bg-premium-primary text-white shadow-lg' : 'text-premium-secondary hover:text-premium-text'}`}
                                    >
                                        Verification Logs
                                    </button>
                                </div>

                                {subTab === 'form' ? (
                                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                                        <div className="glass-card h-fit">
                                            <h2 className="text-xl font-semibold mb-6">NIN Verification</h2>
                                            <form onSubmit={handleVerify} className="space-y-4">
                                                <div>
                                                    <label className="text-sm text-premium-secondary mb-1 block">National Identity Number</label>
                                                    <div className="relative">
                                                        <input
                                                            type="text"
                                                            className="input-field w-full pl-10"
                                                            placeholder="Enter 11-digit NIN"
                                                            value={nin}
                                                            onChange={(e) => setNin(e.target.value)}
                                                        />
                                                        <Search className="absolute left-3 top-2.5 text-premium-secondary" size={18} />
                                                    </div>
                                                </div>
                                                <button type="submit" disabled={loading} className="btn-primary w-full py-3">
                                                    {loading ? 'Processing...' : 'Verify Now'}
                                                </button>
                                            </form>
                                        </div>

                                        {result && (
                                            <div className="glass-card animate-in fade-in slide-in-from-bottom-4 lg:col-span-2">
                                                <h2 className="text-xl font-semibold mb-6 flex justify-between items-center">
                                                    <div className="flex items-center gap-4">
                                                        <span>Verification Results</span>
                                                        <div className="flex gap-2">
                                                            <button
                                                                onClick={() => handlePrint(result)}
                                                                className="flex items-center gap-2 px-3 py-1 bg-premium-primary/10 text-premium-primary rounded-lg text-xs font-bold hover:bg-premium-primary hover:text-premium-text transition-all"
                                                            >
                                                                <Printer size={14} /> Print
                                                            </button>
                                                            <button
                                                                onClick={() => handleDownload(result)}
                                                                className="flex items-center gap-2 px-3 py-1 bg-premium-accent/10 text-premium-accent rounded-lg text-xs font-bold hover:bg-premium-accent hover:text-premium-text transition-all"
                                                            >
                                                                <Download size={14} /> Download
                                                            </button>
                                                        </div>
                                                    </div>
                                                    <span className="text-xs font-mono text-premium-secondary">TX: {result.data?.transaction_id}</span>
                                                </h2>

                                                <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
                                                    {/* Photo Section */}
                                                    <div className="md:col-span-1">
                                                        {result.data?.image ? (
                                                            <img
                                                                src={`data:image/jpeg;base64,${result.data.image}`}
                                                                className="w-full aspect-[3/4] object-cover rounded-lg border border-premium-border shadow-2xl"
                                                                alt="Identity Photo"
                                                            />
                                                        ) : (
                                                            <div className="w-full aspect-[3/4] rounded-lg border border-premium-border border-dashed flex items-center justify-center text-premium-secondary">
                                                                No Photo
                                                            </div>
                                                        )}
                                                    </div>

                                                    {/* Data Sections */}
                                                    <div className="md:col-span-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
                                                        {/* Group 1: Personal Info */}
                                                        <div className="space-y-4">
                                                            <h3 className="text-xs font-bold text-premium-primary uppercase tracking-widest border-b border-premium-border pb-1">Personal</h3>
                                                            <InfoRow label="First Name" value={result.data?.fname} />
                                                            <InfoRow label="Middle Name" value={result.data?.mname} />
                                                            <InfoRow label="Last Name" value={result.data?.lname} />
                                                            <InfoRow label="Date of Birth" value={result.data?.dob} />
                                                            <InfoRow label="Phone Number" value={result.data?.phone} />
                                                        </div>

                                                        {/* Group 2: Origin Info */}
                                                        <div className="space-y-4">
                                                            <h3 className="text-xs font-bold text-premium-primary uppercase tracking-widest border-b border-premium-border pb-1">Origin</h3>
                                                            <InfoRow label="State of Origin" value={result.data?.stateOfOrigin} />
                                                            <InfoRow label="LGA of Origin" value={result.data?.lgaOfOrigin} />
                                                            <InfoRow label="Town" value={result.data?.town} />
                                                        </div>

                                                        {/* Group 3: Residence Info */}
                                                        <div className="space-y-4">
                                                            <h3 className="text-xs font-bold text-premium-primary uppercase tracking-widest border-b border-premium-border pb-1">Residence</h3>
                                                            <InfoRow label="Address" value={result.data?.residenceAdress} />
                                                            <InfoRow label="Town" value={result.data?.residenceTown} />
                                                            <InfoRow label="LGA" value={result.data?.residenceLga} />
                                                            <InfoRow label="State" value={result.data?.residenceState} />
                                                        </div>

                                                        {/* Group 4: Wallet Impact */}
                                                        <div className="sm:col-span-2 lg:col-span-3 bg-premium-overlay p-4 rounded-lg grid grid-cols-2 md:grid-cols-4 gap-4 mt-2">
                                                            <InfoRow label="Units Before" value={result.data?.validation_units_before} />
                                                            <InfoRow label="Units After" value={result.data?.validation_units_after} />
                                                            <div className="col-span-2 flex items-center justify-end">
                                                                <span className="text-xs px-2 py-1 bg-status-emerald/20 text-status-emerald rounded-full font-medium">
                                                                    -1 Unit Consumed
                                                                </span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <div className="glass-card animate-in fade-in slide-in-from-right-4">
                                        <h2 className="text-xl font-semibold mb-6">Verification History</h2>

                                        <FilterBar />

                                        <table className="w-full text-left">
                                            <thead>
                                                <tr className="border-b border-premium-border text-premium-secondary text-sm">
                                                    <th className="pb-4">NIN</th>
                                                    <th className="pb-4">Date</th>
                                                    <th className="pb-4">Name</th>
                                                    <th className="pb-4 text-right">Status</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-premium-border">
                                                {getFilteredData(transactions.filter(t => t.type === 'NIN_VALIDATION'))
                                                    .slice((verifyLogsPage - 1) * ITEMS_PER_PAGE, verifyLogsPage * ITEMS_PER_PAGE)
                                                    .map((tx) => (
                                                        <tr key={tx.id} className="text-sm hover:bg-premium-overlay transition-colors">
                                                            <td className="py-4 font-mono">{tx.details?.nin || '---'}</td>
                                                            <td className="py-4 text-premium-secondary">{new Date(tx.timestamp).toLocaleString()}</td>
                                                            <td className="py-4">{[tx.details?.fname, tx.details?.lname].filter(Boolean).join(' ') || '---'}</td>
                                                            <td className="py-4 text-right">
                                                                <div className="flex items-center justify-end gap-2">
                                                                    <button
                                                                        onClick={() => handlePrint(tx.details)}
                                                                        className="p-2 hover:bg-premium-overlay rounded-lg text-premium-secondary hover:text-premium-text transition-all"
                                                                        title="Print Verification Slip"
                                                                    >
                                                                        <Printer size={16} />
                                                                    </button>
                                                                    <button
                                                                        onClick={() => handleDownload(tx.details)}
                                                                        className="p-2 hover:bg-premium-overlay rounded-lg text-premium-secondary hover:text-premium-text transition-all"
                                                                        title="Download Verification Slip"
                                                                    >
                                                                        <Download size={16} />
                                                                    </button>
                                                                    <span className="px-2 py-1 bg-status-emerald/20 text-status-emerald rounded text-[10px] font-bold uppercase">Verified</span>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    ))}
                                            </tbody>
                                        </table>

                                        {/* Pagination Controls for Verification History */}
                                        {getFilteredData(transactions.filter(t => t.type === 'NIN_VALIDATION')).length > ITEMS_PER_PAGE && (
                                            <div className="mt-6 flex items-center justify-between border-t border-premium-border pt-6">
                                                <div className="text-sm text-premium-secondary">
                                                    Showing <span className="text-premium-text font-bold">{(verifyLogsPage - 1) * ITEMS_PER_PAGE + 1}</span> to <span className="text-premium-text font-bold">{Math.min(verifyLogsPage * ITEMS_PER_PAGE, getFilteredData(transactions.filter(t => t.type === 'NIN_VALIDATION')).length)}</span> of <span className="text-premium-text font-bold">{getFilteredData(transactions.filter(t => t.type === 'NIN_VALIDATION')).length}</span> logs
                                                </div>
                                                <div className="flex gap-2">
                                                    <button
                                                        onClick={() => setVerifyLogsPage(p => Math.max(1, p - 1))}
                                                        disabled={verifyLogsPage === 1}
                                                        className="btn-secondary py-2 px-4 text-xs disabled:opacity-50"
                                                    >
                                                        Previous
                                                    </button>
                                                    <button
                                                        onClick={() => setVerifyLogsPage(p => Math.min(Math.ceil(getFilteredData(transactions.filter(t => t.type === 'NIN_VALIDATION')).length / ITEMS_PER_PAGE), p + 1))}
                                                        disabled={verifyLogsPage === Math.ceil(getFilteredData(transactions.filter(t => t.type === 'NIN_VALIDATION')).length / ITEMS_PER_PAGE)}
                                                        className="btn-primary py-2 px-4 text-xs disabled:opacity-50"
                                                    >
                                                        Next
                                                    </button>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        )}
                        {activeTab === 'audit' && (
                            <div className="glass-card">
                                <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
                                    <FileText className="text-premium-primary" />
                                    Audit Logs
                                </h2>

                                <FilterBar />

                                <table className="w-full text-left">
                                    <thead>
                                        <tr className="border-b border-premium-border text-premium-secondary text-sm">
                                            <th className="pb-4">Action</th>
                                            <th className="pb-4">Date</th>
                                            <th className="pb-4">Actor</th>
                                            <th className="pb-4">Details</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-premium-border">
                                        {getFilteredData(transactions.filter(t => !['NIN_VALIDATION', 'UNIT_PURCHASE'].includes(t.type)))
                                            .slice((auditPage - 1) * ITEMS_PER_PAGE, auditPage * ITEMS_PER_PAGE)
                                            .map((tx) => (
                                                <tr key={tx.id} className="text-sm hover:bg-premium-overlay transition-colors">
                                                    <td className="py-4 font-medium">
                                                        <span className={`px-2 py-1 rounded text-[10px] font-bold uppercase 
                                                        ${tx.type.includes('USER') ? 'bg-status-blue/20 text-status-blue' : 'bg-premium-overlay text-premium-text'}`}>
                                                            {tx.type.replace('_', ' ')}
                                                        </span>
                                                    </td>
                                                    <td className="py-4 text-premium-secondary">{new Date(tx.timestamp).toLocaleString()}</td>
                                                    <td className="py-4 font-medium">{tx.details?.actor || tx.username}</td>
                                                    <td className="py-4 text-premium-secondary">
                                                        {tx.details?.info || tx.details?.reason || '---'}
                                                        {tx.details?.created_user && <span>Created {tx.details.created_user}</span>}
                                                        {tx.details?.deleted_user && <span>Deleted {tx.details.deleted_user}</span>}
                                                        {tx.details?.updated_user && <span>Updated {tx.details.updated_user}</span>}
                                                    </td>
                                                </tr>
                                            ))}
                                    </tbody>
                                </table>

                                {/* Pagination Controls for Audit Logs */}
                                {getFilteredData(transactions.filter(t => !['NIN_VALIDATION', 'UNIT_PURCHASE'].includes(t.type))).length > ITEMS_PER_PAGE && (
                                    <div className="mt-6 flex items-center justify-between border-t border-premium-border pt-6">
                                        <div className="text-sm text-premium-secondary">
                                            Showing <span className="text-premium-text font-bold">{(auditPage - 1) * ITEMS_PER_PAGE + 1}</span> to <span className="text-premium-text font-bold">{Math.min(auditPage * ITEMS_PER_PAGE, getFilteredData(transactions.filter(t => !['NIN_VALIDATION', 'UNIT_PURCHASE'].includes(t.type))).length)}</span> of <span className="text-premium-text font-bold">{getFilteredData(transactions.filter(t => !['NIN_VALIDATION', 'UNIT_PURCHASE'].includes(t.type))).length}</span> logs
                                        </div>
                                        <div className="flex gap-2">
                                            <button
                                                onClick={() => setAuditPage(p => Math.max(1, p - 1))}
                                                disabled={auditPage === 1}
                                                className="btn-secondary py-2 px-4 text-xs disabled:opacity-50"
                                            >
                                                Previous
                                            </button>
                                            <button
                                                onClick={() => setAuditPage(p => Math.min(Math.ceil(getFilteredData(transactions.filter(t => !['NIN_VALIDATION', 'UNIT_PURCHASE'].includes(t.type))).length / ITEMS_PER_PAGE), p + 1))}
                                                disabled={auditPage === Math.ceil(getFilteredData(transactions.filter(t => !['NIN_VALIDATION', 'UNIT_PURCHASE'].includes(t.type))).length / ITEMS_PER_PAGE)}
                                                className="btn-primary py-2 px-4 text-xs disabled:opacity-50"
                                            >
                                                Next
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}


                        {activeTab === 'history' && (
                            <div className="glass-card">
                                <h2 className="text-xl font-semibold mb-6">Activity History</h2>

                                <FilterBar />

                                <table className="w-full text-left">
                                    <thead>
                                        <tr className="border-b border-premium-border text-premium-secondary text-sm">
                                            <th className="pb-4">Type</th>
                                            <th className="pb-4">Date</th>
                                            <th className="pb-4">Actor</th>
                                            <th className="pb-4">Details</th>
                                            <th className="pb-4 text-right">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-premium-border">
                                        {getFilteredData(transactions)
                                            .slice((historyPage - 1) * ITEMS_PER_PAGE, historyPage * ITEMS_PER_PAGE)
                                            .map((tx) => (
                                                <tr key={tx.id} className="text-sm hover:bg-premium-overlay transition-colors">
                                                    <td className="py-4 font-medium">
                                                        <span className={`px-2 py-1 rounded text-xs font-bold uppercase 
                                                ${tx.type === 'USER_CREATION' ? 'bg-status-blue/20 text-status-blue' :
                                                                tx.type === 'USER_DELETION' ? 'bg-status-red/20 text-status-red' :
                                                                    tx.type === 'USER_UPDATE' ? 'bg-status-amber/20 text-status-amber' :
                                                                        tx.type === 'UNIT_PURCHASE' ? 'bg-emerald-500/20 text-emerald-400' :
                                                                            'bg-premium-overlay text-premium-text'}`}>
                                                            {tx.type.replace('_', ' ')}
                                                        </span>
                                                    </td>
                                                    <td className="py-4 text-premium-secondary">{new Date(tx.timestamp).toLocaleString()}</td>
                                                    <td className="py-4 font-medium text-premium-text">
                                                        {tx.details?.actor || tx.username}
                                                    </td>
                                                    <td className="py-4 text-premium-secondary">
                                                        {tx.type === 'UNIT_PURCHASE' && (
                                                            <span>Purchased <b>{tx.amount}</b> units for <b>₦{tx.details?.price_paid?.toLocaleString()}</b></span>
                                                        )}
                                                        {tx.details?.created_user && <span>Created user <b>{tx.details.created_user}</b> as {tx.details.role}</span>}
                                                        {tx.details?.deleted_user && <span>Deleted user <b>{tx.details.deleted_user}</b></span>}
                                                        {tx.details?.updated_user && (
                                                            <span>
                                                                {tx.details.action === 'SUSPENDED' ? 'Suspended' :
                                                                    tx.details.action === 'ACTIVATED' ? 'Activated' : 'Updated'}
                                                                <b> {tx.details.updated_user}</b>
                                                                {tx.details.action ? '' : `: ${tx.details.changes?.join(', ')}`}
                                                            </span>
                                                        )}
                                                        {!tx.details?.created_user && !tx.details?.deleted_user && !tx.details?.updated_user &&
                                                            <span>{tx.details?.info || tx.details?.reason || '---'}</span>}
                                                    </td>
                                                    <td className="py-4 text-right">
                                                        <span className="px-2 py-1 bg-premium-accent/20 text-premium-accent rounded text-xs">Success</span>
                                                    </td>
                                                </tr>
                                            ))}
                                    </tbody>
                                </table>

                                {/* Pagination Controls for History */}
                                {getFilteredData(transactions).length > ITEMS_PER_PAGE && (
                                    <div className="mt-6 flex items-center justify-between border-t border-premium-border pt-6">
                                        <div className="text-sm text-premium-secondary">
                                            Showing <span className="text-premium-text font-bold">{(historyPage - 1) * ITEMS_PER_PAGE + 1}</span> to <span className="text-premium-text font-bold">{Math.min(historyPage * ITEMS_PER_PAGE, getFilteredData(transactions).length)}</span> of <span className="text-premium-text font-bold">{getFilteredData(transactions).length}</span> entries
                                        </div>
                                        <div className="flex gap-2">
                                            <button
                                                onClick={() => setHistoryPage(p => Math.max(1, p - 1))}
                                                disabled={historyPage === 1}
                                                className="btn-secondary py-1 px-4 text-xs disabled:opacity-50"
                                            >
                                                Previous
                                            </button>
                                            <button
                                                onClick={() => setHistoryPage(p => Math.min(Math.ceil(getFilteredData(transactions).length / ITEMS_PER_PAGE), p + 1))}
                                                disabled={historyPage === Math.ceil(getFilteredData(transactions).length / ITEMS_PER_PAGE)}
                                                className="btn-primary py-1 px-4 text-xs disabled:opacity-50"
                                            >
                                                Next
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}


                        {activeTab === 'team' && (
                            <div className="space-y-8">
                                {/* Create User Form */}
                                <div className="glass-card">
                                    <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
                                        <Users className="text-premium-primary" />
                                        Add Team Member
                                    </h2>
                                    <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <label className="text-sm text-premium-secondary block mb-1">Username</label>
                                            <input
                                                className="input-field w-full"
                                                required
                                                value={newUser.username}
                                                onChange={e => setNewUser({ ...newUser, username: e.target.value })}
                                            />
                                        </div>
                                        <div>
                                            <label className="text-sm text-premium-secondary block mb-1">Email</label>
                                            <input
                                                type="email"
                                                className="input-field w-full"
                                                required
                                                value={newUser.email}
                                                onChange={e => setNewUser({ ...newUser, email: e.target.value })}
                                            />
                                        </div>
                                        <div>
                                            <label className="text-sm text-premium-secondary block mb-1">Telephone</label>
                                            <input
                                                type="tel"
                                                className="input-field w-full"
                                                value={newUser.telephone}
                                                onChange={e => setNewUser({ ...newUser, telephone: e.target.value })}
                                                placeholder="+234..."
                                            />
                                        </div>


                                        <div>
                                            <label className="text-sm text-premium-secondary block mb-1">Password</label>
                                            <PasswordInput
                                                required
                                                value={newUser.password}
                                                onChange={e => setNewUser({ ...newUser, password: e.target.value })}
                                            />
                                        </div>
                                        <div>
                                            <label className="text-sm text-premium-secondary block mb-1">Role</label>
                                            <select
                                                className="input-field w-full"
                                                value={newUser.role}
                                                onChange={e => setNewUser({ ...newUser, role: e.target.value })}
                                            >
                                                <option value="user">Standard User</option>
                                                <option value="IDENTITY">Identity Verification Only</option>
                                                <option value="WALLET">Wallet Manager Only</option>
                                                <option value="IDENTITY,WALLET">Full Access</option>
                                            </select>
                                        </div>
                                        <div className="md:col-span-2">
                                            <button
                                                type="submit"
                                                disabled={createLoading}
                                                className="btn-primary w-full py-3"
                                            >
                                                {createLoading ? 'Creating...' : 'Create Team Member'}
                                            </button>
                                        </div>
                                    </form>
                                </div>

                                {/* User List */}
                                <div className="glass-card">
                                    <h2 className="text-xl font-semibold mb-6">Team Members</h2>
                                    <table className="w-full text-left">
                                        <thead>
                                            <tr className="border-b border-premium-border text-premium-secondary text-sm">
                                                <th className="pb-4">Username</th>
                                                <th className="pb-4">Email</th>
                                                <th className="pb-4">Role</th>
                                                <th className="pb-4">Status</th>
                                                <th className="pb-4 text-right">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-premium-border">
                                            {orgUsers.slice((teamPage - 1) * ITEMS_PER_PAGE, teamPage * ITEMS_PER_PAGE).map(u => (
                                                <tr key={u.id} className="text-sm hover:bg-premium-overlay transition-colors">
                                                    <td className="py-4 font-medium">{u.username}</td>
                                                    <td className="py-4 text-premium-secondary">{u.email}</td>
                                                    <td className="py-4"><span className="code-badge">{u.role}</span></td>
                                                    <td className="py-4">
                                                        <span className={`px-2 py-1 rounded text-xs ${u.is_active ? 'bg-status-emerald/20 text-status-emerald' : 'bg-status-red/20 text-status-red'}`}>
                                                            {u.is_active ? 'Active' : 'Inactive'}
                                                        </span>
                                                    </td>
                                                    <td className="py-4 text-right">
                                                        <div className="flex items-center justify-end gap-2">
                                                            <button
                                                                onClick={() => handleToggleUserSuspension(u)}
                                                                className={`p-2 rounded-lg transition-all ${u.is_active ? 'text-status-red hover:bg-status-red/10' : 'text-status-emerald hover:bg-green-400/10'}`}
                                                                title={u.is_active ? "Suspend User" : "Activate User"}
                                                            >
                                                                {u.is_active ? <XCircle size={16} /> : <CheckCircle size={16} />}
                                                            </button>
                                                            <button
                                                                onClick={() => {
                                                                    setEditingUser(u);
                                                                    setIsEditModalOpen(true);
                                                                }}
                                                                className="p-2 hover:bg-premium-overlay rounded-lg text-premium-secondary hover:text-premium-text transition-all"
                                                                title="Edit Role"
                                                            >
                                                                <Edit2 size={16} />
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            ))}
                                            {orgUsers.length === 0 && (
                                                <tr>
                                                    <td colSpan="5" className="py-8 text-center text-premium-secondary">No team members found</td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>

                                    {/* Pagination Controls for Team */}
                                    {orgUsers.length > ITEMS_PER_PAGE && (
                                        <div className="mt-6 flex items-center justify-between border-t border-premium-border pt-6">
                                            <div className="text-sm text-premium-secondary">
                                                Page <span className="text-premium-text font-bold">{teamPage}</span> of <span className="text-premium-text font-bold">{Math.ceil(orgUsers.length / ITEMS_PER_PAGE)}</span>
                                            </div>
                                            <div className="flex gap-2">
                                                <button
                                                    onClick={() => setTeamPage(p => Math.max(1, p - 1))}
                                                    disabled={teamPage === 1}
                                                    className="btn-secondary py-1 px-4 text-xs disabled:opacity-50"
                                                >
                                                    Previous
                                                </button>
                                                <button
                                                    onClick={() => setTeamPage(p => Math.min(Math.ceil(orgUsers.length / ITEMS_PER_PAGE), p + 1))}
                                                    disabled={teamPage === Math.ceil(orgUsers.length / ITEMS_PER_PAGE)}
                                                    className="btn-primary py-1 px-4 text-xs disabled:opacity-50"
                                                >
                                                    Next
                                                </button>
                                            </div>
                                        </div>
                                    )}
                                </div>

                                {/* Edit Role Modal */}
                                {isEditModalOpen && editingUser && (
                                    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                                        <div className="glass-card max-w-sm w-full p-6 space-y-6">
                                            <h3 className="text-xl font-bold">Edit Role</h3>
                                            <p className="text-sm text-premium-secondary">Update permissions for <span className="text-premium-text font-medium">{editingUser.username}</span></p>

                                            <div className="space-y-4">
                                                <div>
                                                    <label className="text-sm text-premium-secondary block mb-1">Role Assignment</label>
                                                    <select
                                                        className="input-field w-full"
                                                        value={editingUser.role}
                                                        onChange={e => setEditingUser({ ...editingUser, role: e.target.value })}
                                                    >
                                                        <option value="user">Standard User</option>
                                                        <option value="IDENTITY">Identity Verification Only</option>
                                                        <option value="WALLET">Wallet Manager Only</option>
                                                        <option value="IDENTITY,WALLET">Full Access</option>
                                                    </select>
                                                </div>
                                                <div className="flex gap-4 pt-2">
                                                    <button
                                                        onClick={() => setIsEditModalOpen(false)}
                                                        className="btn-secondary flex-1"
                                                    >
                                                        Cancel
                                                    </button>
                                                    <button
                                                        onClick={handleUpdateUserRole}
                                                        className="btn-primary flex-1"
                                                    >
                                                        Save Changes
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {activeTab === 'docs' && (
                            <div className="glass-card max-w-4xl mx-auto space-y-8">
                                <h2 className="text-2xl font-bold">API Documentation</h2>
                                <div className="space-y-6">
                                    <section>
                                        <h3 className="text-lg font-semibold text-premium-primary mb-2">Endpoint: POST /verify-nin</h3>
                                        <p className="text-premium-secondary mb-4">Validate a NIN and retrieve biological data.</p>
                                        <div className="bg-black/40 p-4 rounded-lg overflow-x-auto">
                                            <pre className="text-sm">
                                                {`curl -X POST "http://localhost:8000/verify-nin?nin=74756011111" \\
     -H "Authorization: Bearer <your_token>"`}
                                            </pre>
                                        </div>
                                    </section>
                                    <section>
                                        <h3 className="text-lg font-semibold text-premium-primary mb-2">Authentication</h3>
                                        <p className="text-premium-secondary">All endpoints require a Bearer Token obtained via the login endpoint.</p>
                                    </section>
                                </div>
                            </div>
                        )}

                        {activeTab === 'branding' && (
                            <div className="glass-card max-w-2xl">
                                <h2 className="text-xl font-semibold mb-6">White Labelling Settings</h2>
                                <div className="space-y-4">
                                    <div>
                                        <label className="text-sm text-premium-secondary block mb-1">Organisation Name</label>
                                        <input
                                            className="input-field w-full"
                                            value={branding.name}
                                            onChange={(e) => updateBranding({ name: e.target.value })}
                                        />
                                    </div>
                                    <div>
                                        <label className="text-sm text-premium-secondary block mb-1">Logo Text (Initial)</label>
                                        <input
                                            className="input-field w-full"
                                            value={branding.logoText}
                                            onChange={(e) => updateBranding({ logoText: e.target.value })}
                                        />
                                    </div>
                                </div>
                            </div>
                        )}

                    </div>
                </>
            )}

            {/* Hidden/Off-screen Area for Assets generation */}
            <div className="fixed -left-[2000px] top-0 pointer-events-none">
                <div ref={slipRef} style={{ width: '800px' }}>
                    <VerificationSlip result={printableResult} branding={branding} />
                </div>
            </div>

            {/* Hidden Printable Area for window.print() */}
            <div className="hidden print:block fixed inset-0 z-[9999] bg-white">
                <VerificationSlip result={printableResult} branding={branding} />
            </div>
        </div>
    );
};

const NavItem = ({ icon, label, active, onClick }) => (
    <button
        onClick={onClick}
        className={`w-full flex items-center gap-3 p-3 rounded-lg transition-all ${active ? 'bg-premium-primary text-white shadow-lg' : 'text-premium-secondary hover:text-premium-text hover:bg-premium-overlay'}`}
    >
        {icon}
        <span className="font-medium">{label}</span>
    </button>
);

const InfoRow = ({ label, value }) => (
    <div>
        <p className="text-xs text-premium-secondary uppercase mb-1">{label}</p>
        <p className="font-semibold">{value || 'N/A'}</p>
    </div>
);

export default Dashboard;
