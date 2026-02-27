import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    CheckCircle, XCircle, Search, Building2, Shield, Trash2, User, Mail, X,
    Plus, Edit2, Globe, Database, Pause, Play
} from 'lucide-react';
import PasswordInput from '../components/PasswordInput';
import { useDialog } from '../context/DialogContext';

import { API_BASE_URL } from '../config';
const API = API_BASE_URL;

const OrganisationsView = ({
    myPermissions = [],
    isSuperAdmin = false
}) => {
    const canCreate = isSuperAdmin || myPermissions.includes('CREATE_ORGANISATION');
    const canEdit = isSuperAdmin || myPermissions.includes('EDIT_ORGANISATION');
    const canDelete = isSuperAdmin || myPermissions.includes('DELETE_ORGANISATION');
    const canViewWallet = isSuperAdmin || myPermissions.includes('VIEW_ORG_WALLET');

    const [orgs, setOrgs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [editingOrg, setEditingOrg] = useState(null);
    const [viewingOrg, setViewingOrg] = useState(null);
    const [tiers, setTiers] = useState([]);
    const [currentPage, setCurrentPage] = useState(1);
    const ORGS_PER_PAGE = 6;

    const { showDialog } = useDialog();

    const [formData, setFormData] = useState({
        name: '', slug: '', logo: null, primary_color: '#3B82F6', secondary_color: '#64748B',
        admin_username: '', admin_email: '', admin_password: '', admin_password_confirm: '', admin_telephone: '',
        tier_id: '', custom_unit_cost: '', subscription_price: '500000'
    });

    const [randomSuffix, setRandomSuffix] = useState('');

    const generateSlug = (name, suffix) => {
        if (!name) return '';
        const base = name.substring(0, 5).toUpperCase().replace(/[^A-Z0-9]/g, '');
        return `${base}-${suffix}`;
    };

    const handleNameChange = (newName) => {
        if (!editingOrg) {
            const newSlug = generateSlug(newName, randomSuffix);
            setFormData(prev => ({ ...prev, name: newName, slug: newSlug }));
        } else {
            setFormData(prev => ({ ...prev, name: newName }));
        }
    };

    const fetchOrgs = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get(`${API}/admin/organisations`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setOrgs(res.data);
        } catch (err) {
            console.error("Failed to fetch orgs", err);
        }
        setLoading(false);
    };

    const fetchTiers = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get(`${API}/admin/tiers`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setTiers(res.data);
        } catch (err) {
            console.error("Failed to fetch tiers", err);
        }
    };

    useEffect(() => {
        fetchOrgs();
        fetchTiers();
    }, []);

    const filteredOrgs = orgs.filter(o =>
        o.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        o.slug.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const totalPages = Math.ceil(filteredOrgs.length / ORGS_PER_PAGE);
    const paginatedOrgs = filteredOrgs.slice(
        (currentPage - 1) * ORGS_PER_PAGE,
        currentPage * ORGS_PER_PAGE
    );

    useEffect(() => {
        setCurrentPage(1);
    }, [searchTerm]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (formData.admin_password && formData.admin_password !== formData.admin_password_confirm) {
            showDialog({ type: 'error', title: 'Validation Error', message: "Passwords do not match!" });
            return;
        }

        try {
            const token = localStorage.getItem('token');
            const data = new FormData();
            Object.keys(formData).forEach(key => {
                if (formData[key] !== null && formData[key] !== '') {
                    data.append(key, formData[key]);
                }
            });

            if (editingOrg) {
                await axios.put(`${API}/admin/organisations/${editingOrg.id}`, data, {
                    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'multipart/form-data' }
                });
            } else {
                await axios.post(`${API}/admin/organisations`, data, {
                    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'multipart/form-data' }
                });
            }
            setIsModalOpen(false);
            showDialog({
                type: 'success',
                title: editingOrg ? 'Organisation Updated' : 'Organisation Created',
                message: editingOrg
                    ? `Successfully saved ${formData.name}.`
                    : `Successfully saved ${formData.name}. A verification email has been sent to the email address and the user needs to be verified.`
            });
            fetchOrgs();
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Save Failed',
                message: err.response?.data?.detail || "Action failed"
            });
        }
    };

    const handleToggleSuspension = (org) => {
        const action = org.is_suspended ? 'Activate' : 'Suspend';
        showDialog({
            type: 'confirm',
            title: `${action} Organisation`,
            message: `Are you sure you want to ${action.toLowerCase()} ${org.name}? ${org.is_suspended ? 'All users will be reactivated.' : 'All users associated with this organisation will also be suspended automatically.'}`,
            confirmText: `Confirm ${action}`,
            isPasswordRequired: true,
            onConfirm: async (password) => {
                if (!password) {
                    showDialog({ type: 'error', title: 'Password Required', message: 'You must provide your administrator password to confirm this action.' });
                    return;
                }
                try {
                    const token = localStorage.getItem('token');
                    const res = await axios.post(`${API}/admin/organisations/${org.id}/toggle-suspension`, { password }, {
                        headers: { Authorization: `Bearer ${token}` }
                    });
                    showDialog({
                        type: 'success',
                        title: 'Success',
                        message: res.data.message
                    });
                    fetchOrgs();
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

    // Organisation deletion removed in favor of suspension

    return (
        <div className="space-y-6 animate-in slide-in-from-right-4 duration-500">
            <div className="flex justify-between items-center glass-card p-6 bg-white/5 mx-[-1rem] sm:mx-0">
                <div>
                    <h2 className="text-2xl font-bold">Organisations</h2>
                    <p className="text-premium-secondary">Manage multi-tenant workspaces and branding</p>
                </div>
                <div className="flex gap-4">
                    <div className="relative w-64 hidden sm:block">
                        <Search className="absolute left-3 top-2.5 text-premium-secondary" size={18} />
                        <input
                            type="text"
                            className="input-field w-full pl-10 h-10"
                            placeholder="Filter organisations..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                    {canCreate && (
                        <button
                            onClick={() => {
                                setRandomSuffix(Math.floor(1000 + Math.random() * 9000).toString());
                                setEditingOrg(null);
                                setFormData({
                                    name: '', slug: '', logo: null, primary_color: '#3B82F6', secondary_color: '#64748B',
                                    admin_username: '', admin_email: '', admin_password: '', admin_password_confirm: '', admin_telephone: '',
                                    tier_id: '', custom_unit_cost: '', subscription_price: '500000'
                                });
                                setIsModalOpen(true);
                            }}
                            className="btn-primary flex items-center gap-2 px-6 py-2"
                        >
                            <Plus size={20} /> New Organisation
                        </button>
                    )}
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {paginatedOrgs.map(org => (
                    <div
                        key={org.id}
                        onClick={() => setViewingOrg(org)}
                        className={`glass-card group hover:border-premium-primary/50 transition-all p-6 space-y-4 cursor-pointer relative overflow-hidden ${org.is_suspended ? 'border-status-red/50 shadow-[0_0_15px_rgba(239,68,68,0.1)]' : ''}`}
                    >
                        <div className="flex justify-between items-start">
                            <div className="h-12 w-12 rounded-xl bg-white/5 flex items-center justify-center p-2">
                                {org.logo_url ? <img src={org.logo_url} className="h-full w-full object-contain" /> : <Building2 size={24} className="text-premium-secondary" />}
                            </div>
                            <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                {canEdit && org.slug !== 'default' && (
                                    <>
                                        <button
                                            onClick={(e) => { e.stopPropagation(); handleToggleSuspension(org); }}
                                            className={`p-2 rounded-lg ${org.is_suspended ? 'hover:bg-green-500/10 text-green-400' : 'hover:bg-yellow-500/10 text-yellow-400'}`}
                                            title={org.is_suspended ? 'Activate' : 'Suspend'}
                                        >
                                            {org.is_suspended ? <Play size={18} /> : <Pause size={18} />}
                                        </button>
                                    </>
                                )}
                            </div>
                        </div>
                        <div>
                            <div className="flex justify-between items-center mb-1">
                                <h3 className="text-lg font-bold">{org.name}</h3>
                                {org.is_suspended && (
                                    <div className="flex flex-col items-end gap-1">
                                        <span className="text-[10px] font-black bg-status-red text-premium-text px-2 py-0.5 rounded shadow-lg shadow-status-red/40 uppercase tracking-widest animate-pulse border border-white/20">Flagged</span>
                                        <span className="text-[8px] font-bold text-status-red uppercase">Suspended</span>
                                    </div>
                                )}
                            </div>
                            <div className="flex justify-between items-center text-[10px] font-bold uppercase tracking-widest text-premium-secondary">
                                <span className="text-premium-accent">{org.slug}</span>
                                <span className="bg-premium-primary/10 text-premium-primary px-2 py-0.5 rounded border border-premium-primary/20">{org.tier_name || 'Standard'}</span>
                            </div>
                        </div>
                        <div className="flex gap-2">
                            <div className="flex-1 h-1.5 rounded-full" style={{ backgroundColor: org.primary_color }}></div>
                            <div className="flex-1 h-1.5 rounded-full" style={{ backgroundColor: org.secondary_color }}></div>
                        </div>
                        <div className="pt-4 border-t border-premium-border space-y-3">
                            {canViewWallet && org.slug !== 'default' && (
                                <div className="grid grid-cols-2 gap-3">
                                    <div className="bg-white/5 rounded-lg p-2 border border-white/5 text-center">
                                        <p className="text-[8px] text-premium-secondary uppercase font-bold mb-1">Balance</p>
                                        <span className="text-xs font-bold">{org.balance_units?.toLocaleString()}</span>
                                    </div>
                                    <div className="bg-white/5 rounded-lg p-2 border border-white/5 text-center">
                                        <p className="text-[8px] text-premium-secondary uppercase font-bold mb-1">Total</p>
                                        <span className="text-xs font-bold">{org.cumulative_total_units?.toLocaleString()}</span>
                                    </div>
                                </div>
                            )}
                            <div className="text-[10px] text-premium-secondary flex items-center gap-1"><Globe size={10} /> {org.slug}.randamobile.com</div>
                            <div className="text-[10px] text-premium-accent font-bold uppercase flex items-center gap-1"><Shield size={10} /> {org.admin_username || 'No Admin'}</div>
                        </div>
                    </div>
                ))}
            </div>

            {totalPages > 1 && (
                <div className="flex items-center justify-between glass-card p-4 bg-white/5">
                    <div className="text-sm text-premium-secondary">
                        Showing <span className="text-premium-text font-bold">{(currentPage - 1) * ORGS_PER_PAGE + 1}</span> to <span className="text-premium-text font-bold">{Math.min(currentPage * ORGS_PER_PAGE, filteredOrgs.length)}</span> of <span className="text-premium-text font-bold">{filteredOrgs.length}</span>
                    </div>
                    <div className="flex gap-2">
                        <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} className="btn-secondary py-2 px-4 text-sm disabled:opacity-50">Previous</button>
                        <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} className="btn-primary py-2 px-4 text-sm disabled:opacity-50">Next</button>
                    </div>
                </div>
            )}

            {isModalOpen && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="glass-card max-w-lg w-full p-8 space-y-6 max-h-[90vh] overflow-y-auto">
                        <h3 className="text-xl font-bold">{editingOrg ? 'Edit Organisation' : 'Create Organisation'}</h3>
                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-premium-secondary uppercase">Name</label>
                                    <input type="text" className="input-field w-full" value={formData.name} onChange={e => handleNameChange(e.target.value)} required />
                                </div>
                                <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-premium-secondary uppercase">Slug ID</label>
                                    <input type="text" className="input-field w-full" value={formData.slug} onChange={e => setFormData({ ...formData, slug: e.target.value.toLowerCase().replace(/\s+/g, '-') })} required />
                                </div>
                            </div>
                            <div className="space-y-1">
                                <label className="text-[10px] font-bold text-premium-secondary uppercase">Logo</label>
                                <input type="file" accept="image/*" className="input-field w-full p-2" onChange={e => setFormData({ ...formData, logo: e.target.files[0] })} />
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-premium-secondary uppercase">Primary Color</label>
                                    <input type="color" className="h-10 w-full border border-premium-border rounded cursor-pointer p-1" value={formData.primary_color} onChange={e => setFormData({ ...formData, primary_color: e.target.value })} />
                                </div>
                                <div className="space-y-1">
                                    <label className="text-[10px] font-bold text-premium-secondary uppercase">Accent Color</label>
                                    <input type="color" className="h-10 w-full border border-premium-border rounded cursor-pointer p-1" value={formData.secondary_color} onChange={e => setFormData({ ...formData, secondary_color: e.target.value })} />
                                </div>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <select className="input-field w-full" value={formData.tier_id} onChange={e => setFormData({ ...formData, tier_id: e.target.value })}>
                                    <option value="">Select Tier</option>
                                    {tiers.map(t => <option key={t.id} value={t.id}>{t.name} (₦{t.default_unit_cost})</option>)}
                                </select>
                                <input type="number" className="input-field w-full" placeholder="Price Override" value={formData.custom_unit_cost} onChange={e => setFormData({ ...formData, custom_unit_cost: e.target.value })} />
                            </div>
                            {!editingOrg && (
                                <div className="space-y-4 pt-4 border-t border-premium-border">
                                    <input className="input-field w-full" placeholder="Admin Username" value={formData.admin_username} onChange={e => setFormData({ ...formData, admin_username: e.target.value })} required />
                                    <input className="input-field w-full" placeholder="Admin Email" type="email" value={formData.admin_email} onChange={e => setFormData({ ...formData, admin_email: e.target.value })} required />
                                    <input className="input-field w-full" placeholder="Admin Telephone" value={formData.admin_telephone} onChange={e => setFormData({ ...formData, admin_telephone: e.target.value })} />
                                    <PasswordInput placeholder="Password" value={formData.admin_password} onChange={e => setFormData({ ...formData, admin_password: e.target.value })} required />
                                    <PasswordInput placeholder="Confirm Password" value={formData.admin_password_confirm} onChange={e => setFormData({ ...formData, admin_password_confirm: e.target.value })} required />
                                </div>
                            )}
                            <div className="flex gap-4 pt-6">
                                <button type="button" onClick={() => setIsModalOpen(false)} className="btn-secondary flex-1">Cancel</button>
                                <button type="submit" className="btn-primary flex-1">{editingOrg ? 'Save' : 'Create'}</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {viewingOrg && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="glass-card max-w-2xl w-full p-0 overflow-hidden">
                        <div className="h-24 w-full relative" style={{ background: `linear-gradient(to right, ${viewingOrg.primary_color}, ${viewingOrg.secondary_color})` }}>
                            <button onClick={() => setViewingOrg(null)} className="absolute top-4 right-4 p-2 bg-black/20 hover:bg-black/40 rounded-full text-white"><X size={20} /></button>
                            <div className="absolute -bottom-8 left-8 h-16 w-16 rounded-xl bg-premium-surface border-4 border-premium-surface flex items-center justify-center p-2 shadow-xl">
                                {viewingOrg.logo_url ? <img src={viewingOrg.logo_url} className="h-full w-full object-contain" /> : <Building2 size={24} className="text-premium-secondary" />}
                            </div>
                        </div>
                        <div className="pt-10 px-8 pb-8 space-y-6">
                            <h2 className="text-2xl font-bold">{viewingOrg.name}</h2>
                            <div className="grid grid-cols-2 gap-6">
                                <div>
                                    <p className="text-[10px] text-premium-secondary uppercase font-bold mb-2">Primary Admin</p>
                                    <p className="font-bold">{viewingOrg.admin_username || 'Not Assigned'}</p>
                                    <p className="text-xs text-premium-secondary">{viewingOrg.admin_email}</p>
                                </div>
                                <div>
                                    <p className="text-[10px] text-premium-secondary uppercase font-bold mb-2">Billing & Tier</p>
                                    <p className="font-bold text-premium-primary text-lg">{viewingOrg.tier_name || 'Standard'}</p>
                                    <p className="text-xs">₦{viewingOrg.subscription_price?.toLocaleString()} / Year</p>
                                </div>
                            </div>
                            <button onClick={() => setViewingOrg(null)} className="btn-primary w-full mt-4">Close Details</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default OrganisationsView;
