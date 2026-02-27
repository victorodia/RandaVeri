import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../config';
import { Search, RefreshCcw, FileText, Loader2, X } from 'lucide-react';
import { useDialog } from '../context/DialogContext';

const AuditLogsView = ({
    myPermissions = [],
    isSuperAdmin = false
}) => {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [currentPage, setCurrentPage] = useState(1);

    // Filter State
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');
    const [selectedOrg, setSelectedOrg] = useState('');
    const [selectedUser, setSelectedUser] = useState('');

    // Metadata for dropdowns
    const [orgs, setOrgs] = useState([]);
    const [users, setUsers] = useState([]);

    const LOGS_PER_PAGE = 10;
    const { showDialog } = useDialog();

    const token = localStorage.getItem('token');
    const headers = { Authorization: `Bearer ${token}` };

    const fetchMetadata = async () => {
        try {
            if (isSuperAdmin) {
                const orgsRes = await axios.get('http://localhost:8000/admin/organisations', { headers });
                setOrgs(orgsRes.data);
            }

            const usersRes = await axios.get('http://localhost:8000/admin/users', { headers });
            setUsers(usersRes.data);
        } catch (err) {
            console.error("Failed to fetch filter metadata", err);
        }
    };

    const fetchLogs = async () => {
        setLoading(true);
        try {
            const params = new URLSearchParams();
            if (startDate) params.append('start_date', startDate);
            if (endDate) params.append('end_date', endDate);
            if (selectedOrg) params.append('org_id', selectedOrg);
            if (selectedUser) params.append('user_id', selectedUser);

            const res = await axios.get(`${API_BASE_URL}/admin/transactions?${params.toString()}`, { headers });
            setLogs(res.data);
        } catch (err) {
            console.error("Failed to fetch logs", err);
        } finally {
            setLoading(false);
        }
    };

    const clearFilters = () => {
        setStartDate('');
        setEndDate('');
        setSelectedOrg('');
        setSelectedUser('');
        setSearchTerm('');
    };

    useEffect(() => {
        fetchMetadata();
        fetchLogs();
    }, []);

    // Re-fetch when specific filters change (auto-apply)
    useEffect(() => {
        fetchLogs();
    }, [startDate, endDate, selectedOrg, selectedUser]);

    const filteredLogs = logs.filter(log => {
        const text = searchTerm.toLowerCase();
        const userMatch = (log.username || "").toLowerCase().includes(text);
        const typeMatch = (log.type || "").toLowerCase().includes(text);
        const orgMatch = (log.org_name || "").toLowerCase().includes(text);
        return userMatch || typeMatch || orgMatch;
    });

    const totalPages = Math.ceil(filteredLogs.length / LOGS_PER_PAGE);
    const paginatedLogs = filteredLogs.slice(
        (currentPage - 1) * LOGS_PER_PAGE,
        currentPage * LOGS_PER_PAGE
    );

    useEffect(() => {
        setCurrentPage(1);
    }, [searchTerm, startDate, endDate, selectedOrg, selectedUser]);

    const renderDetailsSummary = (log) => {
        const d = log.details || {};
        if (log.type === 'UNIT_PURCHASE') {
            return `Purchased ${log.amount} units for $${d.price_paid?.toFixed(2) || '0.00'}`;
        }
        if (log.type === 'NIN_VALIDATION') {
            return `Validated NIN for ${d.fname || '---'} ${d.lname || '---'}`;
        }
        if (log.type === 'ADMIN_ADJUST') {
            return `Admin adjusted ${log.amount} units`;
        }
        if (d.created_user) return `Created user ${d.created_user}`;
        if (d.deleted_user) return `Deleted user ${d.deleted_user}`;
        if (d.updated_user) return `Updated user ${d.updated_user}`;

        return d.info || d.reason || 'No additional details';
    };

    return (
        <div className="space-y-6 animate-in fade-in duration-500">
            <div className="p-6 glass-card space-y-4 bg-premium-overlay">
                <div className="flex justify-between items-center">
                    <h2 className="text-xl font-bold flex items-center gap-2">
                        <FileText className="text-premium-primary" />
                        Transaction Audit Logs
                    </h2>
                    <button onClick={fetchLogs} className="btn-secondary flex items-center gap-2 py-2 px-4 shadow-sm">
                        <RefreshCcw size={18} className={loading ? "animate-spin" : ""} />
                        Refresh
                    </button>
                </div>

                {/* Filter Bar */}
                <div className={`grid grid-cols-1 md:grid-cols-2 ${isSuperAdmin ? 'lg:grid-cols-5' : 'lg:grid-cols-4'} gap-4 pt-4 border-t border-premium-border/50`}>
                    <div className="space-y-1">
                        <label className="text-[10px] font-bold text-premium-secondary uppercase">Start Date</label>
                        <input
                            type="date"
                            className="input-field w-full h-10 text-xs"
                            value={startDate}
                            onChange={(e) => setStartDate(e.target.value)}
                        />
                    </div>
                    <div className="space-y-1">
                        <label className="text-[10px] font-bold text-premium-secondary uppercase">End Date</label>
                        <input
                            type="date"
                            className="input-field w-full h-10 text-xs"
                            value={endDate}
                            onChange={(e) => setEndDate(e.target.value)}
                        />
                    </div>
                    {isSuperAdmin && (
                        <div className="space-y-1">
                            <label className="text-[10px] font-bold text-premium-secondary uppercase">Organisation</label>
                            <select
                                className="input-field w-full h-10 text-xs"
                                value={selectedOrg}
                                onChange={(e) => setSelectedOrg(e.target.value)}
                            >
                                <option value="">All Organisations</option>
                                {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
                            </select>
                        </div>
                    )}
                    <div className="space-y-1">
                        <label className="text-[10px] font-bold text-premium-secondary uppercase">User</label>
                        <select
                            className="input-field w-full h-10 text-xs"
                            value={selectedUser}
                            onChange={(e) => setSelectedUser(e.target.value)}
                        >
                            <option value="">All Users</option>
                            {users.map(u => <option key={u.id} value={u.id}>{u.username} ({u.organisation_name || 'Staff'})</option>)}
                        </select>
                    </div>
                    <div className="flex items-end gap-2">
                        <div className="relative flex-1">
                            <Search className="absolute left-3 top-2.5 text-premium-secondary" size={18} />
                            <input
                                type="text"
                                className="input-field w-full pl-10 h-10 text-xs"
                                placeholder="Snapshot search..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                        </div>
                        <button
                            onClick={clearFilters}
                            className="p-2.5 bg-status-red/10 text-status-red hover:bg-status-red/20 rounded-lg transition-colors border border-status-red/20"
                            title="Clear All Filters"
                        >
                            <X className="w-5 h-5" />
                        </button>
                    </div>
                </div>
            </div>

            <div className="glass-card overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead className="bg-premium-overlay text-premium-secondary text-sm">
                            <tr>
                                <th className="px-6 py-4 text-left">Timestamp</th>
                                <th className="px-6 py-4 text-left">Organisation</th>
                                <th className="px-6 py-4 text-left">User</th>
                                <th className="px-6 py-4 text-left">Action</th>
                                <th className="px-6 py-4 text-left">Amount/Units</th>
                                <th className="px-6 py-4 text-left">Balance Change</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-premium-border">
                            {loading && logs.length === 0 ? (
                                <tr>
                                    <td colSpan="6" className="px-6 py-10 text-center text-premium-secondary">
                                        <Loader2 className="animate-spin mx-auto text-premium-primary mb-2" />
                                        <span>Loading audit trails...</span>
                                    </td>
                                </tr>
                            ) : paginatedLogs.length > 0 ? paginatedLogs.map(log => (
                                <tr key={log.id} className="hover:bg-premium-overlay transition-colors">
                                    <td className="px-6 py-4 text-xs font-mono text-premium-secondary">
                                        {new Date(log.timestamp).toLocaleString()}
                                    </td>
                                    <td className="px-6 py-4">
                                        <div className="flex flex-col">
                                            <span className="font-medium text-premium-text">{log.org_name}</span>
                                            <span className="text-[10px] text-premium-secondary">ID: {log.org_id}</span>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 font-semibold text-premium-text">{log.username || "Deleted User"}</td>
                                    <td className="px-6 py-4">
                                        <div className="flex flex-col">
                                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase inline-block w-max ${log.type === 'NIN_VALIDATION' ? 'bg-premium-accent/20 text-premium-accent' :
                                                log.type === 'ADMIN_ADJUST' ? 'bg-premium-primary/20 text-premium-primary' :
                                                    'bg-premium-overlay text-premium-secondary'
                                                }`}>
                                                {log.type || "UNKNOWN"}
                                            </span>
                                            <span className="text-xs text-premium-secondary mt-1 max-w-[200px] truncate" title={renderDetailsSummary(log)}>
                                                {renderDetailsSummary(log)}
                                            </span>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 text-premium-text">{log.amount || 0}</td>
                                    <td className="px-6 py-4 text-sm font-mono text-premium-secondary">
                                        {log.units_before} → {log.units_after}
                                    </td>
                                </tr>
                            )) : (
                                <tr>
                                    <td colSpan="6" className="px-6 py-10 text-center text-premium-secondary italic">
                                        No transaction logs found matching your criteria.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
                <div className="flex items-center justify-between glass-card p-4 bg-premium-overlay">
                    <div className="text-sm text-premium-secondary">
                        Showing <span className="text-premium-text font-bold">{(currentPage - 1) * LOGS_PER_PAGE + 1}</span> to <span className="text-premium-text font-bold">{Math.min(currentPage * LOGS_PER_PAGE, filteredLogs.length)}</span> of <span className="text-premium-text font-bold">{filteredLogs.length}</span> logs
                    </div>
                    <div className="flex gap-2">
                        <button
                            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                            disabled={currentPage === 1}
                            className="btn-secondary py-2 px-4 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            Previous
                        </button>
                        <div className="flex items-center gap-1 px-4 text-sm font-bold">
                            <span className="text-premium-primary">{currentPage}</span>
                            <span className="text-premium-secondary">/</span>
                            <span>{totalPages}</span>
                        </div>
                        <button
                            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                            disabled={currentPage === totalPages}
                            className="btn-primary py-2 px-4 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            Next
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AuditLogsView;
