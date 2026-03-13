import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../config';
import {
    Users, Wallet, Globe, Shield, RefreshCcw,
    FileText, TrendingUp, Settings, Activity,
    LogOut, Database, Loader2, Zap, Building2, Layers,
    TrendingDown, ArrowUpRight, AlertCircle, History, Trophy,
    Menu as MenuIcon, X as CloseIcon
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import UsersView from './UsersView';
import AuditLogsView from './AuditLogsView';
import AnalyticsView from './AnalyticsView';
import SystemSettingsView from './SystemSettingsView';
import OrganisationsView from './OrganisationsView';
import TiersView from './TiersView';
import RolesView from './RolesView';
import { useDialog } from '../context/DialogContext';
import ThemeToggle from '../components/ThemeToggle';

const AdminDashboard = () => {
    const { user } = useAuth();

    // Determine which tabs this user can see
    const perms = new Set(user?.permissions || []);
    const isSuperAdmin = user?.role === 'admin' || user?.is_system_role === true;
    const canManageRoles = perms.has('MANAGE_ROLES');

    const TAB_ACCESS = [
        { id: 'users', label: 'Users', icon: <Users size={18} />, show: true },
        { id: 'roles', label: 'Roles', icon: <Shield size={18} />, show: canManageRoles || isSuperAdmin },
        { id: 'orgs', label: 'Organisations', icon: <Building2 size={18} />, show: true },
        { id: 'tiers', label: 'Tiers', icon: <Layers size={18} />, show: true },
        { id: 'logs', label: 'Audit Logs', icon: <FileText size={18} />, show: true },
        { id: 'analytics', label: 'Analytics', icon: <TrendingUp size={18} />, show: true },
    ].filter(t => t.show);

    const firstTab = TAB_ACCESS[0]?.id || 'users';
    const [activeTab, setActiveTab] = useState(firstTab);
    const [users, setUsers] = useState([]);
    const [stats, setStats] = useState(null);
    const [health, setHealth] = useState(null);
    const [loading, setLoading] = useState(true);
    const { showDialog } = useDialog();
    const [showRevenueModal, setShowRevenueModal] = useState(false);
    const [revenuePage, setRevenuePage] = useState(1);
    const REVENUE_PER_PAGE = 5;

    const { logout } = useAuth();
    const token = localStorage.getItem('token');
    const [platformName, setPlatformName] = useState('Admin Portal');
    const [isMenuOpen, setIsMenuOpen] = useState(false);
    const headers = { Authorization: `Bearer ${token}` };

    const fetchData = async () => {
        setLoading(true);
        // Fetch each independently so one failure doesn't block others
        try {
            const usersRes = await axios.get(`${API_BASE_URL}/admin/users`, { headers });
            setUsers(usersRes.data);
        } catch (err) {
            console.error("Failed to fetch users", err);
        }

        // The stats and health fetching logic is now handled by the new useEffect below
        // This fetchData will primarily be for users and other data that needs to be refreshed
        // independently or on specific actions.
        setLoading(false);
    };

    useEffect(() => {
        if (!token) return;
        const headers = { Authorization: `Bearer ${token}` };
        setLoading(true);
        Promise.all([
            axios.get(`${API_BASE_URL}/admin/stats`, { headers }),
            axios.get(`${API_BASE_URL}/admin/health`, { headers }),
            axios.get(`${API_BASE_URL}/admin/config`, { headers }),
        ]).then(([statsRes, healthRes, configRes]) => {
            setStats(statsRes.data);
            setHealth(healthRes.data);
            if (configRes.data?.org_name) setPlatformName(configRes.data.org_name);
        }).catch(err => {
            console.error('Dashboard load error:', err);
        }).finally(() => setLoading(false));
    }, [token]);

    useEffect(() => {
        fetchData();
    }, []);

    const handleUpdateUser = async (userId, data) => {
        try {
            await axios.put(`${API_BASE_URL}/admin/users/${userId}`, data, { headers });
            fetchData();
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Update Failed',
                message: err.response?.data?.detail || "Update failed"
            });
        }
    };

    const handleBulkAction = async (userIds, action, units = 0) => {
        try {
            await axios.post(`${API_BASE_URL}/admin/users/bulk`, {
                user_ids: userIds,
                action,
                units
            }, { headers });
            fetchData();
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Bulk Action Failed',
                message: err.response?.data?.detail || "Bulk action failed"
            });
        }
    };

    const handleAdjustWallet = async (userId, units) => {
        try {
            await axios.post(`${API_BASE_URL}/admin/adjust-wallet/${userId}?units=${units}`, {}, { headers });
            fetchData();
            return true;
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Action Failed',
                message: err.response?.data?.detail || "Action failed"
            });
            return false;
        }
    };

    const handleToggleUserSuspension = async (userId, password) => {
        try {
            await axios.post(`${API_BASE_URL}/admin/users/${userId}/toggle-suspension`, { password }, { headers });
            fetchData();
            return true;
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Action Failed',
                message: err.response?.data?.detail || "Action failed"
            });
            return false;
        }
    };

    if (loading && !stats) {
        return (
            <div className="min-h-screen bg-premium-bg flex items-center justify-center">
                <div className="text-center">
                    <Loader2 className="animate-spin text-premium-primary mx-auto mb-4" size={48} />
                    <p className="text-premium-secondary animate-pulse">Initializing Control Center...</p>
                </div>
            </div>
        );
    }

    const RevenueModal = () => (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-300">
            <div className="glass-card w-full max-w-2xl max-h-[80vh] overflow-hidden flex flex-col border border-white/20 shadow-2xl">
                <div className="p-6 border-b border-premium-border flex justify-between items-center bg-premium-overlay">
                    <h2 className="text-xl font-bold flex items-center gap-2">
                        <Building2 className="text-emerald-400" />
                        Revenue Breakdown by Organisation
                    </h2>
                    <button
                        onClick={() => setShowRevenueModal(false)}
                        className="p-2 hover:bg-premium-overlay rounded-full transition-colors"
                    >
                        <RefreshCcw className="rotate-45" size={24} />
                    </button>
                </div>
                <div className="flex-1 overflow-y-auto p-6">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="text-premium-secondary text-xs uppercase tracking-wider border-b border-white/10">
                                <th className="pb-3 bg-transparent">Organisation</th>
                                <th className="pb-3 text-right">Revenue Contribution</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                            {(stats?.revenue_breakdown || [])
                                .slice((revenuePage - 1) * REVENUE_PER_PAGE, revenuePage * REVENUE_PER_PAGE)
                                .map((org, i) => {
                                    const actualIndex = (revenuePage - 1) * REVENUE_PER_PAGE + i + 1;
                                    return (
                                        <tr key={actualIndex} className="group hover:bg-white/5 transition-colors">
                                            <td className="py-4 bg-transparent border-none">
                                                <div className="flex items-center gap-3">
                                                    <div className="w-8 h-8 rounded bg-premium-primary/10 flex items-center justify-center text-premium-primary font-bold text-xs">
                                                        {actualIndex}
                                                    </div>
                                                    <span className="font-semibold">{org.name}</span>
                                                </div>
                                            </td>
                                            <td className="py-4 text-right font-mono text-emerald-400 font-bold bg-transparent border-none">
                                                ₦{org.revenue.toLocaleString()}
                                            </td>
                                        </tr>
                                    );
                                })}
                        </tbody>
                    </table>
                    {(stats?.revenue_breakdown || []).length > REVENUE_PER_PAGE && (
                        <div className="mt-4 flex items-center justify-between border-t border-white/10 pt-4">
                            <div className="text-xs text-premium-secondary">
                                Page <span className="text-premium-text font-bold">{revenuePage}</span> of <span className="text-premium-text font-bold">{Math.ceil(stats.revenue_breakdown.length / REVENUE_PER_PAGE)}</span>
                            </div>
                            <div className="flex gap-2">
                                <button
                                    onClick={() => setRevenuePage(p => Math.max(1, p - 1))}
                                    disabled={revenuePage === 1}
                                    className="p-2 hover:bg-white/10 rounded-lg text-premium-secondary disabled:opacity-30"
                                >
                                    <RefreshCcw size={14} className="rotate-180" />
                                </button>
                                <button
                                    onClick={() => setRevenuePage(p => Math.min(Math.ceil(stats.revenue_breakdown.length / REVENUE_PER_PAGE), p + 1))}
                                    disabled={revenuePage === Math.ceil(stats.revenue_breakdown.length / REVENUE_PER_PAGE)}
                                    className="p-2 hover:bg-white/10 rounded-lg text-premium-secondary disabled:opacity-30"
                                >
                                    <RefreshCcw size={14} />
                                </button>
                            </div>
                        </div>
                    )}
                    {(!stats?.revenue_breakdown || stats.revenue_breakdown.length === 0) && (
                        <p className="text-center py-12 text-premium-secondary italic">No revenue records found</p>
                    )}
                </div>
                <div className="p-4 bg-white/5 border-t border-white/10 flex justify-between items-center">
                    <span className="text-premium-secondary text-sm">Total Revenue:</span>
                    <span className="text-xl font-bold text-premium-text">₦{(stats?.total_revenue || 0).toLocaleString()}</span>
                </div>
            </div>
        </div>
    );

    return (
        <div className="min-h-screen bg-premium-bg text-premium-text pb-20 overflow-x-hidden">
            {/* Top Navigation Bar */}
            <div className="border-b border-premium-border bg-premium-surface/30 backdrop-blur-md sticky top-0 z-40">
                <div className="max-w-[1600px] mx-auto px-4 sm:px-8 h-20 flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2 sm:gap-4 shrink-0">
                        <div className="h-10 w-10 bg-premium-primary/10 rounded-xl overflow-hidden flex items-center justify-center border border-premium-primary/20">
                            <img
                                src={
                                    user?.organisation?.logo_url
                                        ? (user.organisation.logo_url.startsWith('/uploads') ? `${API_BASE_URL}${user.organisation.logo_url}` : user.organisation.logo_url)
                                        : "/logo.jpeg"
                                }
                                alt="Logo"
                                className="h-full w-full object-cover"
                                onError={(e) => { e.target.src = "/logo.jpeg"; }}
                            />
                        </div>
                        <div className="hidden xsm:block">
                            <h1 className="text-lg sm:text-xl font-bold tracking-tight truncate max-w-[150px] sm:max-w-none">
                                {platformName} <span className="text-premium-primary">Admin</span>
                            </h1>
                            <div className="flex items-center gap-2">
                                <span className={`h-1.5 w-1.5 rounded-full ${health?.status === 'Healthy' ? 'bg-emerald-500' : 'bg-amber-500'}`} />
                                <span className="text-[8px] sm:text-[10px] text-premium-secondary uppercase tracking-widest font-bold">Online • {health?.latency_ms}ms</span>
                            </div>
                        </div>
                    </div>

                    <div className="flex items-center gap-2 sm:gap-6">
                        {/* Desktop Tabs */}
                        <div className="hidden lg:flex bg-premium-bg rounded-xl p-1 border border-premium-border shadow-inner">
                            {TAB_ACCESS.map(tab => (
                                <TabButton
                                    key={tab.id}
                                    active={activeTab === tab.id}
                                    onClick={() => setActiveTab(tab.id)}
                                    icon={tab.icon}
                                    label={tab.label}
                                />
                            ))}
                        </div>

                        <div className="flex items-center gap-2">
                            <ThemeToggle />
                            <div className="h-6 w-[1px] bg-premium-border mx-1 hidden sm:block" />
                            <button
                                onClick={() => setIsMenuOpen(!isMenuOpen)}
                                className="lg:hidden p-2.5 bg-premium-surface/50 border border-premium-border rounded-xl text-premium-text hover:bg-premium-overlay transition-all"
                            >
                                {isMenuOpen ? <CloseIcon size={20} /> : <MenuIcon size={20} />}
                            </button>
                            <button onClick={logout} className="p-2.5 hover:bg-red-500/10 text-red-500 rounded-xl transition-all border border-transparent hover:border-red-500/20 group hidden sm:flex">
                                <LogOut size={20} className="group-hover:translate-x-0.5 transition-transform" />
                            </button>
                        </div>
                    </div>
                </div>

                {/* Mobile Navigation Dropdown */}
                {isMenuOpen && (
                    <div className="lg:hidden bg-premium-surface border-b border-premium-border animate-in slide-in-from-top duration-300">
                        <div className="p-4 grid grid-cols-2 gap-2">
                            {TAB_ACCESS.map(tab => (
                                <button
                                    key={tab.id}
                                    onClick={() => { setActiveTab(tab.id); setIsMenuOpen(false); }}
                                    className={`flex flex-col items-center justify-center gap-2 p-4 rounded-xl text-xs font-bold transition-all border ${activeTab === tab.id
                                        ? 'bg-premium-primary/10 border-premium-primary text-premium-primary'
                                        : 'bg-premium-bg border-premium-border text-premium-secondary hover:text-premium-text'
                                        }`}
                                >
                                    {React.cloneElement(tab.icon, { size: 20 })}
                                    {tab.label}
                                </button>
                            ))}
                            <button
                                onClick={logout}
                                className="flex flex-col items-center justify-center gap-2 p-4 rounded-xl text-xs font-bold bg-red-500/5 border border-red-500/20 text-red-500 col-span-2 mt-2"
                            >
                                <LogOut size={20} />
                                Logout Session
                            </button>
                        </div>
                    </div>
                )}
            </div>

            <div className="max-w-[1600px] mx-auto px-4 sm:px-8 py-6 sm:py-10">
                {/* Stats Summary - Optimized for all screens */}
                <div className="grid grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-3 sm:gap-4 mb-6 sm:mb-10">
                    <SummaryCard
                        icon={<Users />}
                        label="Total Users"
                        value={stats?.total_users}
                        color="blue"
                        onClick={() => setActiveTab('users')}
                    />
                    <SummaryCard
                        icon={<Building2 />}
                        label="Revenue"
                        value={perms.has('VIEW_REVENUE') || isSuperAdmin ? `₦${(stats?.total_revenue || 0).toLocaleString()}` : "₦ ••••••••"}
                        color="emerald"
                        trend={perms.has('VIEW_REVENUE') || isSuperAdmin ? "View Breakdown" : "Restricted"}
                        onClick={() => (perms.has('VIEW_REVENUE') || isSuperAdmin) && setShowRevenueModal(true)}
                    />
                    <SummaryCard
                        icon={<Database />}
                        label="Circulation"
                        value={stats?.total_units_in_circulation}
                        color="purple"
                        onClick={() => setActiveTab('orgs')}
                        trend="Across all Organisations"
                    />
                    <SummaryCard
                        icon={<Globe />}
                        label="Master Wallet"
                        value={stats?.master_wallet_units}
                        color={stats?.master_wallet_units < 500 ? "red" : "purple"}
                        trend="System Liquidity"
                        alert={stats?.master_wallet_units < 500}
                    />
                    <SummaryCard
                        icon={<Activity />}
                        label="Total Volume"
                        value={stats?.total_transactions}
                        color="amber"
                        onClick={() => setActiveTab('logs')}
                        trend={`${stats?.success_rate || 100}% Success`}
                    />
                    <SummaryCard
                        icon={<Trophy />}
                        label="Top Client"
                        value={stats?.top_orgs?.[0]?.name || "None"}
                        color="amber"
                        onClick={() => setActiveTab('orgs')}
                        trend={`${stats?.top_orgs?.[0]?.count || 0} NIN`}
                    />
                    <SummaryCard
                        icon={<History />}
                        label="Latest Event"
                        value={(stats?.recent_activity?.[0]?.action || "None").replace(/_/g, ' ')}
                        color="blue"
                        onClick={() => setActiveTab('logs')}
                        trend={`by ${stats?.recent_activity?.[0]?.username || 'system'}`}
                    />
                </div>

                {showRevenueModal && <RevenueModal />}

                {/* Main Content Area */}
                <main>
                    <div className="flex-1 overflow-y-auto p-0 sm:p-2 lg:p-8">
                        {TAB_ACCESS.length === 0 && (
                            <div className="flex flex-col items-center justify-center py-24 text-center">
                                <div className="p-4 bg-premium-primary/10 rounded-full mb-4">
                                    <Shield size={32} className="text-premium-primary" />
                                </div>
                                <h3 className="text-xl font-bold mb-2">Limited Access Account</h3>
                                <p className="text-premium-secondary max-w-sm">
                                    Your account has been granted <strong className="text-premium-text">API-level</strong> permissions only.
                                    Contact your administrator to request dashboard access.
                                </p>
                            </div>
                        )}
                        {activeTab === 'users' && <UsersView
                            users={users}
                            onUpdateUser={handleUpdateUser}
                            onBulkAction={handleBulkAction}
                            onAdjustWallet={handleAdjustWallet}
                            onToggleSuspension={handleToggleUserSuspension}
                            myPermissions={Array.from(perms)}
                            isSuperAdmin={isSuperAdmin}
                        />}
                        {activeTab === 'roles' && <RolesView
                            myPermissions={Array.from(perms)}
                            isSuperAdmin={isSuperAdmin}
                        />}
                        {activeTab === 'orgs' && <OrganisationsView
                            myPermissions={Array.from(perms)}
                            isSuperAdmin={isSuperAdmin}
                        />}
                        {activeTab === 'tiers' && <TiersView
                            myPermissions={Array.from(perms)}
                            isSuperAdmin={isSuperAdmin}
                        />}
                        {activeTab === 'logs' && <AuditLogsView
                            myPermissions={Array.from(perms)}
                            isSuperAdmin={isSuperAdmin}
                        />}
                        {activeTab === 'analytics' && <AnalyticsView
                            myPermissions={Array.from(perms)}
                            isSuperAdmin={isSuperAdmin}
                        />}
                    </div>
                </main>
            </div>
        </div>
    );
};

const TabButton = ({ active, onClick, icon, label }) => (
    <button
        onClick={onClick}
        className={`flex items-center gap-2 px-6 py-2.5 rounded-lg text-sm font-bold transition-all duration-300 ${active
            ? 'bg-premium-primary text-white shadow-lg shadow-premium-primary/20'
            : 'text-premium-secondary hover:text-premium-text hover:bg-premium-overlay'
            }`}
    >
        {icon}
        {label}
    </button>
);

const SummaryCard = ({ icon, label, value, color, trend, onClick, alert }) => {
    const colors = {
        blue: 'text-status-blue bg-status-blue/10',
        emerald: 'text-status-emerald bg-status-emerald/10',
        purple: 'text-status-purple bg-status-purple/10',
        amber: 'text-status-amber bg-status-amber/10',
        red: 'text-status-red bg-status-red/10'
    };
    return (
        <div
            onClick={onClick}
            className={`glass-card !p-4 sm:!p-6 border-b-2 border-b-transparent hover:border-b-premium-primary transition-all duration-300 group ${onClick ? 'cursor-pointer' : ''} ${alert ? 'animate-pulse border-red-500/50' : ''}`}
        >
            <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                    <p className="text-premium-secondary text-[8px] sm:text-[10px] uppercase tracking-widest font-bold mb-1 truncate">{label}</p>
                    <p className={`text-lg sm:text-2xl font-bold tabular-nums truncate ${alert ? 'text-red-500' : ''}`}>
                        {typeof value === 'number' ? value.toLocaleString() : (value || '0')}
                    </p>
                    {trend && (
                        <div className="flex items-center gap-1 mt-1 sm:mt-2">
                            <TrendingUp size={10} className={alert ? 'text-red-500' : 'text-premium-accent'} />
                            <p className={`text-[8px] sm:text-[10px] font-bold uppercase truncate ${alert ? 'text-red-500' : 'text-premium-accent'}`}>{trend}</p>
                        </div>
                    )}
                </div>
                <div className={`h-8 w-8 sm:h-10 sm:w-10 rounded-xl flex items-center justify-center transition-transform group-hover:scale-110 shrink-0 ${colors[color] || colors.blue}`}>
                    {React.cloneElement(icon, { size: 18 })}
                </div>
            </div>
            {alert && (
                <div className="mt-4 flex items-center gap-2 text-red-500 text-[10px] font-bold uppercase animate-bounce">
                    <AlertCircle size={12} /> Critical: Low Balance
                </div>
            )}
        </div>
    );
};

export default AdminDashboard;
