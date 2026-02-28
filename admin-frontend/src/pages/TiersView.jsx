
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../config';
import { Layers, Plus, Edit2, Trash2, X, CheckCircle, Info } from 'lucide-react';
import Banner from '../components/Banner';

const TiersView = ({
    myPermissions = [],
    isSuperAdmin = false
}) => {
    const canCreate = isSuperAdmin || myPermissions.includes('CREATE_TIER');
    const canEdit = isSuperAdmin || myPermissions.includes('EDIT_TIER');
    const canDelete = isSuperAdmin || myPermissions.includes('DELETE_TIER');

    const [tiers, setTiers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [currentPage, setCurrentPage] = useState(1);
    const TIERS_PER_PAGE = 6;
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [editingTier, setEditingTier] = useState(null);
    const [formData, setFormData] = useState({ name: '', default_unit_cost: 1.0 });
    const [banner, setBanner] = useState({ message: '', type: 'error' });

    const fetchTiers = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get(`${API_BASE_URL}/admin/tiers`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setTiers(res.data);
        } catch (err) {
            console.error("Failed to fetch tiers", err);
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchTiers();
    }, []);

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const token = localStorage.getItem('token');
            if (editingTier) {
                await axios.put(`${API_BASE_URL}/admin/tiers/${editingTier.id}`, formData, {
                    headers: { Authorization: `Bearer ${token}` }
                });
            } else {
                await axios.post(`${API_BASE_URL}/admin/tiers`, formData, {
                    headers: { Authorization: `Bearer ${token}` }
                });
            }
            setIsModalOpen(false);
            setEditingTier(null);
            setFormData({ name: '', default_unit_cost: 1.0 });
            setBanner({ message: `Tier ${editingTier ? 'updated' : 'created'} successfully`, type: 'success' });
            fetchTiers();
        } catch (err) {
            setBanner({ message: err.response?.data?.detail || "Action failed", type: 'error' });
        }
    };

    const handleDelete = async (tierId) => {
        if (!window.confirm("Delete this tier?")) return;
        try {
            const token = localStorage.getItem('token');
            await axios.delete(`${API_BASE_URL}/admin/tiers/${tierId}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setBanner({ message: "Tier deleted successfully", type: 'success' });
            fetchTiers();
        } catch (err) {
            setBanner({ message: err.response?.data?.detail || "Delete failed", type: 'error' });
        }
    };

    return (
        <div className="space-y-6 animate-in slide-in-from-right-4 duration-500">
            <Banner
                message={banner.message}
                type={banner.type}
                onClose={() => setBanner({ ...banner, message: '' })}
            />
            <div className="flex justify-between items-center">
                <div>
                    <h2 className="text-2xl font-bold">Standard Tiers</h2>
                    <p className="text-premium-secondary">Define default unit pricing for organisation groups</p>
                </div>
                {canCreate && (
                    <button
                        onClick={() => {
                            setEditingTier(null);
                            setFormData({ name: '', default_unit_cost: 1.0 });
                            setIsModalOpen(true);
                        }}
                        className="btn-primary flex items-center gap-2 px-6 py-3"
                    >
                        <Plus size={20} /> Create Tier
                    </button>
                )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {tiers.slice((currentPage - 1) * TIERS_PER_PAGE, currentPage * TIERS_PER_PAGE).map(tier => (
                    <div key={tier.id} className="glass-card p-6 space-y-4 relative overflow-hidden group">
                        <div className="flex justify-between items-start">
                            <div className="h-10 w-10 rounded-lg bg-premium-primary/10 flex items-center justify-center text-premium-primary">
                                <Layers size={20} />
                            </div>
                            <div className="flex gap-2">
                                {canEdit && (
                                    <button
                                        onClick={() => {
                                            setEditingTier(tier);
                                            setFormData({ name: tier.name, default_unit_cost: tier.default_unit_cost });
                                            setIsModalOpen(true);
                                        }}
                                        className="p-2 hover:bg-white/10 rounded-lg text-premium-secondary hover:text-premium-text"
                                    >
                                        <Edit2 size={16} />
                                    </button>
                                )}
                                {tier.name !== 'Standard' && canDelete && (
                                    <button
                                        onClick={() => handleDelete(tier.id)}
                                        className="p-2 hover:bg-red-500/10 rounded-lg text-premium-secondary hover:text-red-400"
                                    >
                                        <Trash2 size={16} />
                                    </button>
                                )}
                            </div>
                        </div>

                        <div>
                            <h3 className="text-lg font-bold">{tier.name}</h3>
                            <div className="flex items-center gap-2 mt-2">
                                <span className="text-2xl font-bold text-premium-primary">₦{tier.default_unit_cost}</span>
                                <span className="text-xs text-premium-secondary uppercase font-bold tracking-widest">per unit</span>
                            </div>
                        </div>

                        <div className="pt-4 border-t border-premium-border text-[10px] text-premium-secondary flex items-center gap-1 uppercase font-bold">
                            <Info size={10} /> Default price for this tier
                        </div>
                    </div>
                ))}
            </div>

            {/* Pagination Controls */}
            {tiers.length > TIERS_PER_PAGE && (
                <div className="flex items-center justify-between glass-card p-4 bg-premium-overlay border border-premium-border">
                    <div className="text-sm text-premium-secondary">
                        Showing <span className="text-premium-text font-bold">{(currentPage - 1) * TIERS_PER_PAGE + 1}</span> to <span className="text-premium-text font-bold">{Math.min(currentPage * TIERS_PER_PAGE, tiers.length)}</span> of <span className="text-premium-text font-bold">{tiers.length}</span> tiers
                    </div>
                    <div className="flex gap-2">
                        <button
                            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                            disabled={currentPage === 1}
                            className="btn-secondary py-2 px-4 text-sm disabled:opacity-50"
                        >
                            Previous
                        </button>
                        <div className="flex items-center gap-1 px-4 text-sm font-bold">
                            <span className="text-premium-primary">{currentPage}</span>
                            <span className="text-premium-secondary">/</span>
                            <span>{Math.ceil(tiers.length / TIERS_PER_PAGE)}</span>
                        </div>
                        <button
                            onClick={() => setCurrentPage(p => Math.min(Math.ceil(tiers.length / TIERS_PER_PAGE), p + 1))}
                            disabled={currentPage === Math.ceil(tiers.length / TIERS_PER_PAGE)}
                            className="btn-primary py-2 px-4 text-sm disabled:opacity-50"
                        >
                            Next
                        </button>
                    </div>
                </div>
            )}

            {isModalOpen && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="glass-card max-w-sm w-full p-8 space-y-6 animate-in zoom-in duration-300">
                        <div className="flex justify-between items-center">
                            <h3 className="text-xl font-bold">{editingTier ? 'Edit Tier' : 'Create Tier'}</h3>
                            <button onClick={() => setIsModalOpen(false)} className="text-premium-secondary hover:text-premium-text">
                                <X size={20} />
                            </button>
                        </div>

                        <form onSubmit={handleSubmit} className="space-y-4">
                            <div className="space-y-1">
                                <label className="text-xs font-bold text-premium-secondary uppercase text-left">Tier Name</label>
                                <input
                                    type="text"
                                    className="input-field w-full"
                                    value={formData.name}
                                    onChange={e => setFormData({ ...formData, name: e.target.value })}
                                    required
                                    placeholder="e.g. Enterprise, NGO, Startup"
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="text-xs font-bold text-premium-secondary uppercase">Default Unit Cost (₦)</label>
                                <input
                                    type="number"
                                    step="0.01"
                                    className="input-field w-full"
                                    value={formData.default_unit_cost}
                                    onChange={e => setFormData({ ...formData, default_unit_cost: e.target.value })}
                                    required
                                />
                                <p className="text-[10px] text-premium-secondary italic">Price organisations pay per validation unit.</p>
                            </div>

                            <button type="submit" className="btn-primary w-full py-4 font-bold flex items-center justify-center gap-2 mt-4">
                                <CheckCircle size={18} />
                                {editingTier ? 'Update Tier' : 'Create Tier'}
                            </button>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default TiersView;
