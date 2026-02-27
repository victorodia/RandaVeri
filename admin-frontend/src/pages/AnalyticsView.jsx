import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../config';
import {
    AreaChart, Area, XAxis, YAxis, CartesianGrid,
    Tooltip, ResponsiveContainer, BarChart, Bar, Legend,
    PieChart, Pie, Cell
} from 'recharts';
import {
    TrendingUp, Activity, Zap, Clock, Loader2,
    DollarSign, Users, AlertTriangle, Layers, Calendar,
    Award, BarChart3, PieChart as PieIcon, Cpu
} from 'lucide-react';

const AnalyticsView = () => {
    const [overviewData, setOverviewData] = useState({ trends: [], summary: {}, org_breakdown: [] });
    const [extendedData, setExtendedData] = useState(null);
    const [activeTab, setActiveTab] = useState('overview');
    const [days, setDays] = useState(7);
    const [loading, setLoading] = useState(true);
    const [health, setHealth] = useState(null);

    const token = localStorage.getItem('token');
    const headers = { Authorization: `Bearer ${token}` };

    const fetchData = async () => {
        setLoading(true);
        try {
            const [analyticsRes, healthRes, extendedRes] = await Promise.all([
                axios.get(`${API_BASE_URL}/admin/analytics?days=${days}`, { headers }),
                axios.get(`${API_BASE_URL}/admin/health`, { headers }),
                axios.get(`${API_BASE_URL}/admin/analytics/extended`, { headers })
            ]);
            setOverviewData(analyticsRes.data);
            setHealth(healthRes.data);
            setExtendedData(extendedRes.data);
        } catch (err) {
            console.error("Failed to fetch analytics", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, [days]);

    if (loading && !extendedData) return (
        <div className="flex flex-col items-center justify-center p-20 space-y-4">
            <Loader2 className="animate-spin text-premium-primary" size={48} />
            <p className="text-premium-secondary animate-pulse font-bold tracking-widest uppercase text-xs">Architecting Intelligence...</p>
        </div>
    );

    const tabs = [
        { id: 'overview', label: 'Overview', icon: <BarChart3 size={16} /> },
        { id: 'financial', label: 'Financial', icon: <DollarSign size={16} /> },
        { id: 'operations', label: 'Operations', icon: <Cpu size={16} /> },
        { id: 'behavior', label: 'Behavior', icon: <Users size={16} /> },
    ];

    return (
        <div className="space-y-6 animate-in fade-in duration-700">
            {/* Nav Header */}
            <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6 bg-premium-overlay/40 p-6 rounded-3xl glass-card border border-premium-border/20">
                <div className="flex items-center gap-4">
                    <div className="h-12 w-12 rounded-2xl bg-premium-primary/10 flex items-center justify-center border border-premium-primary/20">
                        <Activity className="text-premium-primary" size={24} />
                    </div>
                    <div>
                        <h2 className="text-2xl font-black text-premium-text tracking-tight">Randa Intelligence</h2>
                        <p className="text-premium-secondary text-xs font-bold uppercase tracking-widest">Global Platform Analytics</p>
                    </div>
                </div>

                <div className="flex flex-wrap gap-2 bg-premium-bg/30 p-1.5 rounded-2xl border border-premium-border/50">
                    {tabs.map(tab => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-black transition-all duration-300 ${activeTab === tab.id
                                ? 'bg-premium-primary text-white shadow-[0_4px_15px_rgba(59,130,246,0.3)]'
                                : 'text-premium-secondary hover:text-premium-text hover:bg-premium-border/10'}`}
                        >
                            {tab.icon}
                            {tab.label}
                        </button>
                    ))}
                    <div className="w-[1px] h-6 bg-premium-border/30 mx-2 self-center lg:block hidden" />
                    {[7, 30].map(d => (
                        <button
                            key={d}
                            onClick={() => setDays(d)}
                            className={`px-4 py-2.5 rounded-xl text-xs font-black transition-all ${days === d
                                ? 'bg-premium-secondary/20 text-premium-text'
                                : 'text-premium-secondary hover:text-premium-text'}`}
                        >
                            {d}D
                        </button>
                    ))}
                </div>
            </div>

            {/* Content Rendering */}
            {activeTab === 'overview' && <OverviewTab data={overviewData} health={health} days={days} />}
            {activeTab === 'financial' && <FinancialTab data={extendedData?.financial} />}
            {activeTab === 'operations' && <OperationsTab data={extendedData?.operations} health={health} />}
            {activeTab === 'behavior' && <BehaviorTab data={extendedData} />}
        </div>
    );
};

// --- DATA TABS ---

const OverviewTab = ({ data, health, days }) => {
    const summary = data?.summary || {};
    const trends = data?.trends || [];
    const org_breakdown = data?.org_breakdown || [];
    return (
        <div className="space-y-6 animate-in zoom-in-95 duration-500">
            <div className={`p-4 rounded-2xl border flex items-center justify-between ${health?.status === 'Healthy'
                ? 'bg-emerald-500/5 border-emerald-500/10'
                : 'bg-amber-500/5 border-amber-500/10'
                }`}>
                <div className="flex items-center gap-3">
                    <div className={`h-2 w-2 rounded-full animate-pulse ${health?.status === 'Healthy' ? 'bg-emerald-500 shadow-[0_0_10px_#10B981]' : 'bg-amber-500'}`} />
                    <p className="text-[10px] font-black uppercase tracking-widest text-premium-secondary">
                        System Health: <span className={health?.status === 'Healthy' ? 'text-emerald-400' : 'text-amber-400'}>{health?.status || 'Probing...'}</span>
                    </p>
                </div>
                <Zap size={14} className="text-premium-secondary" />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <MetricCard icon={<TrendingUp />} label="Growth" value={`${summary.growth_rate || 0}%`} sub={`Past ${days} days`} trend={summary.growth_rate >= 0 ? 'up' : 'down'} color="blue" />
                <MetricCard icon={<Zap />} label="Success" value={`${summary.success_rate || 0}%`} sub="Validation Accuracy" color="emerald" />
                <MetricCard icon={<Clock />} label="Peak Hour" value={summary.peak_hour || 'N/A'} sub="Busiest Slot (GMT)" color="purple" />
                <MetricCard icon={<Activity />} label="Volume" value={summary.this_period_validations?.toLocaleString() || '0'} sub="Total Validations" color="amber" />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div className="glass-card p-8">
                    <h3 className="text-lg font-black mb-8 flex items-center gap-3"><div className="h-2 w-2 bg-premium-primary rounded-full shadow-[0_0_10px_#3B82F6]" />Usage Trends</h3>
                    <div className="h-[350px]"><UsageChart data={trends} /></div>
                </div>
                <div className="glass-card p-8">
                    <h3 className="text-lg font-black mb-8 flex items-center gap-3"><div className="h-2 w-2 bg-emerald-500 rounded-full shadow-[0_0_10px_#10B981]" />Top Organisations</h3>
                    <div className="h-[350px]"><OrgVolumeChart data={org_breakdown} /></div>
                </div>
            </div>
        </div>
    );
};

const FinancialTab = ({ data }) => {
    const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#8B5CF6', '#EC4899'];
    return (
        <div className="space-y-8 animate-in slide-in-from-bottom-4 duration-500">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="glass-card p-8 border-l-4 border-l-premium-primary flex flex-col justify-center">
                    <p className="text-[10px] font-black text-premium-secondary uppercase mb-2">Total Est. Profit</p>
                    <h3 className="text-4xl font-black text-premium-text tracking-tighter mb-1 select-all">₦{(data?.profit_stats?.total_profit || 0).toLocaleString()}</h3>
                    <div className="flex items-center gap-2 text-emerald-400 text-[10px] font-black uppercase">
                        <TrendingUp size={12} /> Margin: {data?.profit_stats?.margin_pct?.toFixed(1) || '0.0'}%
                    </div>
                </div>
                <div className="glass-card p-8 group relative overflow-hidden">
                    <DollarSign className="absolute -right-8 -bottom-8 opacity-5 group-hover:opacity-10 transition-opacity" size={160} />
                    <h3 className="text-lg font-black mb-2 flex items-center gap-2 tracking-tight"><DollarSign size={18} className="text-premium-primary" /> Financial Yield</h3>
                    <p className="text-premium-secondary text-xs font-medium leading-relaxed">Profit maximization through dynamic tiered pricing across all client organizations.</p>
                </div>
                <div className="glass-card p-8">
                    <h3 className="text-[10px] font-black text-premium-secondary uppercase mb-6 tracking-widest">Efficiency Benchmark</h3>
                    <div className="space-y-4">
                        <div className="flex justify-between text-xs">
                            <span className="text-premium-secondary font-bold">AVG PROFIT / OP</span>
                            <span className="text-premium-text font-black tracking-tight">
                                ₦{data?.profit_stats?.total_validations > 0
                                    ? (data.profit_stats.total_profit / data.profit_stats.total_validations).toFixed(2)
                                    : '0.00'
                                }
                            </span>
                        </div>
                        <div className="w-full h-1.5 bg-premium-bg/50 rounded-full overflow-hidden leading-none flex">
                            <div className="h-full bg-premium-primary shadow-[0_0_10px_#3B82F6]" style={{ width: '70%' }} />
                        </div>
                    </div>
                </div>
            </div>

            <div className="glass-card p-8">
                <h3 className="text-lg font-black mb-8 flex items-center gap-2 tracking-tight"><Award size={20} className="text-amber-400" /> Customer Lifetime Value (LTV) Leaderboard</h3>
                <div className="h-[400px]">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={data?.ltv || []} margin={{ top: 20, right: 30, left: 20, bottom: 20 }}>
                            <XAxis dataKey="name" stroke="#64748B" fontSize={10} fontWeight="black" axisLine={false} tickLine={false} tick={({ x, y, payload }) => (
                                <g transform={`translate(${x},${y})`}>
                                    <text x={0} y={0} dy={16} textAnchor="middle" fill="#64748B" fontSize={9} fontWeight="black" transform="rotate(-20)">{(payload?.value || '').length > 10 ? payload.value.substring(0, 10) + '...' : (payload?.value || '')}</text>
                                </g>
                            )} />
                            <YAxis stroke="#64748B" fontSize={10} fontWeight="bold" axisLine={false} tickLine={false} tickFormatter={(v) => `₦${(v || 0) / 1000}k`} />
                            <Tooltip contentStyle={{ backgroundColor: '#1A1D23', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '15px', color: '#fff' }} />
                            <Bar dataKey="value" radius={[10, 10, 0, 0]} barSize={45}>
                                {(data?.ltv || []).map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>
        </div>
    );
};

const OperationsTab = ({ data, health }) => {
    return (
        <div className="space-y-8 animate-in zoom-in-95 duration-500">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 glass-card p-8">
                    <div className="flex justify-between items-center mb-10">
                        <h3 className="text-lg font-black flex items-center gap-3 tracking-tight">
                            <Calendar size={20} className="text-purple-400" />
                            Validation Velocity Heatmap (7x24)
                        </h3>
                        <div className="flex gap-1">
                            {[0.1, 0.4, 0.7, 1].map(o => <div key={o} className="h-2 w-2 rounded-sm bg-purple-500/80" style={{ opacity: o }} />)}
                        </div>
                    </div>
                    <HeatmapChart data={data?.heatmap || []} />
                    <div className="mt-8 flex justify-between text-[9px] font-black uppercase tracking-widest text-premium-secondary border-t border-premium-border/10 pt-4">
                        <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:59</span>
                    </div>
                </div>

                <div className="glass-card p-8 h-full flex flex-col">
                    <h3 className="text-lg font-black mb-8 flex items-center gap-3 tracking-tight text-red-400">
                        <AlertTriangle size={20} />
                        Fault Distribution
                    </h3>
                    <div className="flex-1 min-h-[300px]">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={data?.errors?.length > 0 ? data.errors : [{ name: 'No Issues', value: 1 }]}
                                    innerRadius={60}
                                    outerRadius={85}
                                    paddingAngle={10}
                                    dataKey="value"
                                >
                                    {(data?.errors || [{}]).map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={['#EF4444', '#F59E0B', '#3B82F6', '#8B5CF6'][index % 4] || '#3B82F6'} stroke="none" />
                                    ))}
                                </Pie>
                                <Tooltip contentStyle={{ backgroundColor: '#1A1D23', border: 'none', borderRadius: '15px' }} />
                                <Legend verticalAlign="bottom" height={36} wrapperStyle={{ fontSize: '10px', textTransform: 'uppercase', fontWeight: 'black', paddingTop: '20px' }} />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    );
};

const BehaviorTab = ({ data }) => {
    const growth = data?.growth || {};
    const behavior = data?.behavior || {};
    return (
        <div className="space-y-8 animate-in slide-in-from-right-4 duration-500">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div className="glass-card p-8">
                    <h3 className="text-lg font-black mb-8 flex items-center gap-3 tracking-tight"><Users size={20} className="text-premium-primary" /> Top Power Operators</h3>
                    <div className="space-y-4">
                        {(behavior.power_users || []).map((user, idx) => (
                            <div key={user.username} className="flex items-center justify-between p-4 rounded-2xl bg-premium-bg/20 border border-premium-border/10 hover:border-premium-primary/30 transition-all duration-300">
                                <div className="flex items-center gap-4">
                                    <div className="h-10 w-10 rounded-xl bg-premium-overlay flex items-center justify-center text-xs font-black border border-premium-border text-premium-primary">{idx + 1}</div>
                                    <div>
                                        <p className="text-sm font-black text-premium-text tracking-tighter">{user.username}</p>
                                        <p className="text-[10px] text-premium-secondary font-black uppercase tracking-widest">Active Verification Flow</p>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <p className="text-xl font-black text-premium-text">{user.count}</p>
                                    <p className="text-[10px] text-premium-secondary font-black uppercase">Units</p>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="space-y-8">
                    {/* Acquisition Velocity */}
                    <div className="glass-card p-8">
                        <h3 className="text-lg font-black mb-8 flex items-center gap-3 tracking-tight"><TrendingUp size={20} className="text-premium-primary" /> Acquisition Velocity</h3>
                        <div className="h-[200px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={growth?.acquisition || []}>
                                    <XAxis dataKey="date" hide />
                                    <YAxis hide />
                                    <Tooltip contentStyle={{ backgroundColor: '#1A1D23', border: 'none', borderRadius: '15px' }} />
                                    <Area type="step" dataKey="count" stroke="#3B82F6" strokeWidth={3} fill="rgba(59,130,246,0.1)" />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    <div className="glass-card p-8">
                        <h3 className="text-lg font-black mb-10 flex items-center gap-3 tracking-tight"><Layers size={20} className="text-blue-400" /> Subscription Health</h3>
                        <div className="grid grid-cols-2 gap-4">
                            {(growth.sub_health || []).map(item => (
                                <div key={item.name} className="p-6 rounded-3xl border border-premium-border/20 bg-premium-bg/30 relative overflow-hidden group">
                                    <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:rotate-12 transition-transform"><Activity size={40} /></div>
                                    <p className="text-[10px] font-black text-premium-secondary uppercase mb-2 tracking-widest">{item.name}</p>
                                    <p className="text-3xl font-black text-premium-text">{item.value}</p>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="glass-card p-8 border-l-4 border-l-red-500/50">
                        <div className="flex items-center justify-between mb-8">
                            <h3 className="text-lg font-black flex items-center gap-3 tracking-tight italic"><AlertTriangle size={20} className="text-red-400 animate-pulse" /> Churn Risk Monitor</h3>
                            <span className="px-2 py-0.5 rounded-md bg-red-400/10 text-red-400 text-[9px] font-black uppercase tracking-tighter border border-red-400/20 underline decoration-red-400/30 font-mono">CRITICAL</span>
                        </div>
                        <div className="flex flex-wrap gap-2">
                            {(growth.churn_risk || []).length > 0 ? (growth.churn_risk || []).map(org => (
                                <span key={org} className="px-4 py-2 rounded-xl bg-red-500/5 border border-red-500/20 text-red-400 text-[11px] font-black tracking-tighter hover:bg-red-500/10 transition-colors shadow-sm">{org}</span>
                            )) : <p className="text-sm text-emerald-400 font-bold bg-emerald-400/5 p-4 rounded-2xl border border-emerald-400/20 w-full text-center">Perfect Retention Trace - No Attrition Detected</p>}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

// --- CHART UTILS ---

const MetricCard = ({ icon, label, value, sub, trend, color }) => {
    const colorClasses = {
        blue: 'text-blue-400 bg-blue-400/10 border-blue-400/20 shadow-[0_4px_15px_rgba(59,130,246,0.1)]',
        emerald: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20 shadow-[0_4px_15px_rgba(16,185,129,0.1)]',
        purple: 'text-purple-400 bg-purple-400/10 border-purple-400/20 shadow-[0_4px_15px_rgba(139,92,246,0.1)]',
        amber: 'text-amber-400 bg-amber-400/10 border-amber-400/20 shadow-[0_4px_15px_rgba(245,158,11,0.1)]',
    };
    return (
        <div className="glass-card p-8 border-b-2 border-b-transparent hover:border-b-premium-primary transition-all duration-500 group">
            <div className="flex justify-between items-start mb-6">
                <div className={`p-3 rounded-2xl ${colorClasses[color]} transition-transform group-hover:scale-110 duration-500`}>{icon}</div>
                {trend && <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-lg ${trend === 'up' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-500'}`}>{trend === 'up' ? '↑' : '↓'}</span>}
            </div>
            <p className="text-[10px] font-black text-premium-secondary uppercase tracking-[0.3em] mb-1">{label}</p>
            <h4 className="text-4xl font-black text-premium-text tracking-tighter mb-2">{value}</h4>
            <p className="text-[10px] text-premium-secondary font-black uppercase tracking-tighter">{sub}</p>
        </div>
    );
};

const UsageChart = ({ data }) => (
    <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={Array.isArray(data) ? data : []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <XAxis dataKey="date" hide />
            <YAxis hide />
            <Tooltip contentStyle={{ backgroundColor: '#1A1D23', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '15px' }} />
            <Area type="monotone" name="Validations" dataKey="validations" stroke="#3B82F6" strokeWidth={5} fill="rgba(59,130,246,0.05)" />
            <Area type="monotone" name="Revenue" dataKey="revenue" stroke="#10B981" strokeWidth={5} fill="rgba(16,185,129,0.05)" />
        </AreaChart>
    </ResponsiveContainer>
);

const OrgVolumeChart = ({ data }) => (
    <ResponsiveContainer width="100%" height="100%">
        <BarChart data={Array.isArray(data) ? data : []} layout="vertical" margin={{ left: 0, right: 40 }}>
            <XAxis type="number" hide />
            <YAxis dataKey="name" type="category" stroke="#64748B" fontSize={10} width={100} tickLine={false} axisLine={false} fontWeight="black" />
            <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: '#1A1D23', border: 'none', borderRadius: '15px' }} />
            <Bar dataKey="volume" fill="#10B981" radius={[0, 15, 15, 0]} barSize={25} />
        </BarChart>
    </ResponsiveContainer>
);

const HeatmapChart = ({ data }) => {
    const dOrder = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const hours = Array.from({ length: 24 }, (_, i) => i);
    const validData = Array.isArray(data) ? data : [];
    const maxVal = validData.length > 0 ? Math.max(...validData.map(d => d.value || 0), 1) : 1;

    // Create a lookup for efficient data mapping
    const lookup = validData.reduce((acc, curr) => {
        acc[`${curr.day}-${curr.hour}`] = curr.value;
        return acc;
    }, {});

    return (
        <div className="flex flex-col gap-2">
            {dOrder.map(day => (
                <div key={day} className="flex gap-2 items-center group">
                    <span className="w-10 text-[10px] font-black text-premium-secondary uppercase group-hover:text-premium-primary transition-colors">{day}</span>
                    <div className="flex-1 flex gap-1.5 translate-y-0.5">
                        {hours.map(hour => {
                            const val = lookup[`${day}-${hour}`] || 0;
                            return (
                                <div
                                    key={hour}
                                    className="flex-1 h-9 rounded-sm transition-all duration-300 hover:scale-110 hover:z-10 hover:shadow-[0_0_15px_rgba(139,92,246,0.4)] cursor-pointer"
                                    style={{
                                        backgroundColor: '#8B5CF6',
                                        opacity: val === 0 ? 0.04 : (0.15 + (val / maxVal) * 0.85)
                                    }}
                                    title={`${day} ${hour}:00 | Activity: ${val}`}
                                />
                            );
                        })}
                    </div>
                </div>
            ))}
        </div>
    );
};

export default AnalyticsView;
