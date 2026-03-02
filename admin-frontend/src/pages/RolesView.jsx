import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    Plus, Shield, Edit2, Trash2, CheckCircle,
    XCircle, Lock, Info, ChevronRight, Save, ShieldCheck
} from 'lucide-react';
import Banner from '../components/Banner';

import { API_BASE_URL } from '../config';
const API = API_BASE_URL;

// Maps every backend permission key to a display category
const PERMISSION_GROUPS = [
    {
        label: 'User Management',
        keys: ['CREATE_USER', 'EDIT_USER', 'SUSPEND_USER', 'DELETE_USER'],
    },
    {
        label: 'Finance & Reporting',
        keys: ['VIEW_ORG_WALLET', 'VIEW_REVENUE', 'VIEW_TRANSACTIONS', 'VIEW_REPORTS'],
    },
    {
        label: 'Administration',
        keys: ['VIEW_AUDIT_LOGS', 'MANAGE_ROLES', 'MANAGE_SUBSCRIPTION', 'MANAGE_SETTINGS'],
    },
    {
        label: 'Organisations',
        keys: ['CREATE_ORGANISATION', 'EDIT_ORGANISATION', 'DELETE_ORGANISATION'],
    },
    {
        label: 'Tiers',
        keys: ['CREATE_TIER', 'EDIT_TIER', 'DELETE_TIER'],
    },
];

const GROUP_COLORS = {
    'User Management': 'text-status-blue',
    'Finance & Reporting': 'text-status-emerald',
    'Administration': 'text-status-amber',
    'Organisations': 'text-status-cyan',
    'Tiers': 'text-status-teal',
};

const RolesView = ({ myPermissions = [], isSuperAdmin = false }) => {
    const canManageRoles = isSuperAdmin || myPermissions.includes('MANAGE_ROLES');

    const [roles, setRoles] = useState([]);
    const [allPermissions, setAllPermissions] = useState([]);
    const [banner, setBanner] = useState({ message: '', type: 'error' });
    const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
    const [isEditModalOpen, setIsEditModalOpen] = useState(false);
    const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);

    const [editingRole, setEditingRole] = useState(null);
    const [roleToDelete, setRoleToDelete] = useState(null);

    const emptyNew = { name: '', permissions: [] };
    const [newRole, setNewRole] = useState(emptyNew);

    const fetchData = async () => {
        const token = localStorage.getItem('token');
        const headers = { Authorization: `Bearer ${token}` };
        try {
            const [rolesRes, permsRes] = await Promise.all([
                axios.get(`${API}/admin/roles`, { headers }),
                axios.get(`${API}/permissions`, { headers })
            ]);
            setRoles(rolesRes.data);
            setAllPermissions(permsRes.data);
        } catch (err) {
            console.error('Failed to load roles data', err);
            setBanner({ message: 'Failed to load roles data', type: 'error' });
        }
    };

    useEffect(() => {
        fetchData();
    }, []);

    const handleCreateRole = async () => {
        if (!newRole.name) {
            setBanner({ message: 'Role name is required', type: 'error' });
            return;
        }
        try {
            const token = localStorage.getItem('token');
            await axios.post(`${API}/admin/roles`, newRole, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setIsCreateModalOpen(false);
            setNewRole(emptyNew);
            fetchData();
            setBanner({ message: 'Role created successfully', type: 'success' });
        } catch (err) {
            setBanner({ message: err.response?.data?.detail || 'Failed to create role', type: 'error' });
        }
    };

    const handleUpdateRole = async () => {
        try {
            const token = localStorage.getItem('token');
            await axios.put(`${API}/admin/roles/${editingRole.id}`, {
                name: editingRole.name,
                permissions: editingRole.permissions
            }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setIsEditModalOpen(false);
            fetchData();
            setBanner({ message: 'Role updated successfully', type: 'success' });
        } catch (err) {
            setBanner({ message: err.response?.data?.detail || 'Failed to update role', type: 'error' });
        }
    };

    const handleDeleteRole = async () => {
        try {
            const token = localStorage.getItem('token');
            await axios.delete(`${API}/admin/roles/${roleToDelete.id}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setIsDeleteModalOpen(false);
            fetchData();
            setBanner({ message: 'Role deleted successfully', type: 'success' });
        } catch (err) {
            setBanner({ message: err.response?.data?.detail || 'Failed to delete role', type: 'error' });
        }
    };

    // Grouped permission checklist with per-group select-all toggle
    const PermissionChecklist = ({ selected, onChange }) => (
        <div className="space-y-5">
            {PERMISSION_GROUPS.map(group => {
                // Only show permissions that exist in the backend catalogue
                const groupPerms = group.keys
                    .map(key => allPermissions.find(p => p.key === key))
                    .filter(Boolean);

                if (groupPerms.length === 0) return null;

                const allSelected = groupPerms.every(p => selected.includes(p.key));
                const someSelected = groupPerms.some(p => selected.includes(p.key));

                const toggleGroup = () => {
                    if (allSelected) {
                        onChange(selected.filter(k => !group.keys.includes(k)));
                    } else {
                        const toAdd = group.keys.filter(k => !selected.includes(k));
                        onChange([...selected, ...toAdd]);
                    }
                };

                return (
                    <div key={group.label}>
                        {/* Group header */}
                        <div className="flex items-center justify-between mb-2">
                            <span className={`text-[10px] font-black uppercase tracking-widest ${GROUP_COLORS[group.label] || 'text-premium-secondary'}`}>
                                {group.label}
                            </span>
                            <button
                                type="button"
                                onClick={toggleGroup}
                                className="text-[10px] font-bold text-premium-secondary hover:text-premium-primary transition-colors uppercase tracking-wide"
                            >
                                {allSelected ? 'Clear All' : 'Select All'}
                            </button>
                        </div>

                        {/* Permission rows */}
                        <div className="grid grid-cols-1 gap-1.5">
                            {groupPerms.map(perm => {
                                const active = selected.includes(perm.key);
                                return (
                                    <button
                                        key={perm.key}
                                        type="button"
                                        onClick={() =>
                                            onChange(active
                                                ? selected.filter(p => p !== perm.key)
                                                : [...selected, perm.key]
                                            )
                                        }
                                        className={`flex items-start gap-3 px-4 py-3 rounded-xl border text-left transition-all ${active
                                            ? 'border-premium-primary bg-premium-primary/10'
                                            : 'border-premium-border bg-white/5 hover:bg-white/10'
                                            }`}
                                    >
                                        <div className={`mt-0.5 flex-shrink-0 w-4 h-4 rounded border flex items-center justify-center ${active ? 'bg-premium-primary border-premium-primary' : 'border-premium-border'
                                            }`}>
                                            {active && (
                                                <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                                                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                                                </svg>
                                            )}
                                        </div>
                                        <div>
                                            <div className={`text-sm font-semibold ${active ? 'text-white' : 'text-premium-text'}`}>
                                                {perm.label}
                                            </div>
                                            <div className="text-xs text-premium-secondary/70 mt-0.5">{perm.description}</div>
                                        </div>
                                    </button>
                                );
                            })}
                        </div>
                    </div>
                );
            })}
        </div>
    );

    return (
        <div className="space-y-6 animate-in slide-in-from-right-4 duration-500">
            <Banner
                message={banner.message}
                type={banner.type}
                onClose={() => setBanner({ ...banner, message: '' })}
            />

            <div className="glass-card p-6 flex justify-between items-center bg-white/5">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-premium-primary/20 rounded-lg">
                        <Shield className="text-premium-primary" size={24} />
                    </div>
                    <div>
                        <h2 className="text-xl font-bold">Role Management</h2>
                        <p className="text-sm text-premium-secondary">Define and manage permission groups for your team</p>
                    </div>
                </div>
                {canManageRoles && (
                    <button
                        onClick={() => { setNewRole(emptyNew); setIsCreateModalOpen(true); }}
                        className="btn-primary flex items-center gap-2"
                    >
                        <Plus size={18} /> Create New Role
                    </button>
                )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                {roles.map(role => (
                    <div key={role.id} className="glass-card p-6 flex flex-col justify-between bg-white/5 hover:bg-white/10 transition-all group">
                        <div className="space-y-4">
                            <div className="flex justify-between items-start">
                                <div className="flex items-center gap-2">
                                    <div className={`p-1.5 rounded-lg ${role.is_system ? 'bg-amber-500/20' : 'bg-premium-primary/10'}`}>
                                        {role.is_system
                                            ? <ShieldCheck size={16} className="text-amber-400" />
                                            : <Shield size={16} className="text-premium-primary" />
                                        }
                                    </div>
                                    <h3 className="font-bold text-lg">{role.name}</h3>
                                    {role.is_system && (
                                        <span className="flex items-center gap-1 px-2 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-full text-[10px] font-bold uppercase">
                                            <Lock size={9} /> System
                                        </span>
                                    )}
                                </div>
                                <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                    {canManageRoles && !role.is_system && (
                                        <>
                                            <button
                                                onClick={() => { setEditingRole(role); setIsEditModalOpen(true); }}
                                                className="p-1.5 hover:bg-premium-primary/20 text-premium-primary rounded-lg transition-colors"
                                            >
                                                <Edit2 size={16} />
                                            </button>
                                            <button
                                                onClick={() => { setRoleToDelete(role); setIsDeleteModalOpen(true); }}
                                                className="p-1.5 hover:bg-red-500/20 text-red-400 rounded-lg transition-colors"
                                            >
                                                <Trash2 size={16} />
                                            </button>
                                        </>
                                    )}
                                </div>
                            </div>

                            <div className="space-y-2">
                                <div className="text-xs text-premium-secondary uppercase font-bold tracking-wider mb-1">Permissions</div>
                                <div className="flex flex-wrap gap-1.5">
                                    {role.permissions?.slice(0, 5).map(pKey => {
                                        const p = allPermissions.find(ap => ap.key === pKey);
                                        return (
                                            <span key={pKey} className="px-2 py-0.5 bg-premium-primary/10 text-premium-primary rounded text-[10px] uppercase font-bold border border-premium-primary/20">
                                                {p?.label || pKey}
                                            </span>
                                        );
                                    })}
                                    {role.permissions?.length > 5 && (
                                        <span className="px-2 py-0.5 bg-white/10 text-premium-secondary rounded text-[10px] font-bold">
                                            +{role.permissions.length - 5} more
                                        </span>
                                    )}
                                    {(!role.permissions || role.permissions.length === 0) && (
                                        <span className="text-xs text-premium-secondary italic">No permissions assigned</span>
                                    )}
                                </div>
                            </div>
                        </div>

                        <div className="mt-6 pt-4 border-t border-premium-border/50 flex justify-between items-center text-xs text-premium-secondary">
                            <div className="flex items-center gap-1">
                                <Info size={12} />
                                {(role.user_count ?? 0)} Users assigned
                            </div>
                            {!role.is_system ? (
                                <button
                                    onClick={() => { setEditingRole(role); setIsEditModalOpen(true); }}
                                    className="text-premium-primary hover:underline flex items-center gap-1"
                                >
                                    Details <ChevronRight size={12} />
                                </button>
                            ) : (
                                <span className="flex items-center gap-1 text-amber-400/70 italic">
                                    <Lock size={10} /> Protected
                                </span>
                            )}
                        </div>
                    </div>
                ))}
            </div>

            {/* Create Role Modal */}
            {isCreateModalOpen && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="glass-card max-w-lg w-full flex flex-col max-h-[90vh]">
                        <div className="p-8 pb-4 flex items-center gap-3">
                            <div className="p-2 bg-premium-primary/20 rounded-lg">
                                <Plus size={20} className="text-premium-primary" />
                            </div>
                            <h3 className="text-xl font-bold">Create New Role</h3>
                        </div>
                        <div className="px-8 space-y-4">
                            <input
                                type="text"
                                placeholder="Role Name (e.g., Financial Officer)"
                                className="input-field w-full"
                                value={newRole.name}
                                onChange={e => setNewRole({ ...newRole, name: e.target.value })}
                            />
                            <div className="space-y-3">
                                <label className="text-xs text-premium-secondary uppercase font-bold flex justify-between">
                                    Select Permissions
                                    <span>{newRole.permissions.length} selected</span>
                                </label>
                                <div className="max-h-[40vh] overflow-y-auto pr-2 custom-scrollbar">
                                    <PermissionChecklist
                                        selected={newRole.permissions}
                                        onChange={perms => setNewRole({ ...newRole, permissions: perms })}
                                    />
                                </div>
                            </div>
                        </div>
                        <div className="p-8 pt-4 flex gap-4 border-t border-premium-border mt-4">
                            <button onClick={() => setIsCreateModalOpen(false)} className="btn-secondary flex-1">Cancel</button>
                            <button onClick={handleCreateRole} className="btn-primary flex-1">Create Role</button>
                        </div>
                    </div>
                </div>
            )}

            {/* Edit Role Modal */}
            {isEditModalOpen && editingRole && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="glass-card max-w-lg w-full flex flex-col max-h-[90vh]">
                        <div className="p-8 pb-4 flex items-center gap-3">
                            <div className="p-2 bg-premium-primary/20 rounded-lg">
                                <Shield size={20} className="text-premium-primary" />
                            </div>
                            <h3 className="text-xl font-bold">Edit Role: {editingRole.name}</h3>
                        </div>
                        <div className="px-8 space-y-4">
                            <input
                                type="text"
                                placeholder="Role Name"
                                className="input-field w-full"
                                value={editingRole.name}
                                onChange={e => setEditingRole({ ...editingRole, name: e.target.value })}
                            />
                            <div className="space-y-3">
                                <label className="text-xs text-premium-secondary uppercase font-bold flex justify-between">
                                    Permissions
                                    <span>{editingRole.permissions.length} selected</span>
                                </label>
                                <div className="max-h-[40vh] overflow-y-auto pr-2 custom-scrollbar">
                                    <PermissionChecklist
                                        selected={editingRole.permissions}
                                        onChange={perms => setEditingRole({ ...editingRole, permissions: perms })}
                                    />
                                </div>
                            </div>
                        </div>
                        <div className="p-8 pt-4 flex gap-4 border-t border-premium-border mt-4">
                            <button onClick={() => setIsEditModalOpen(false)} className="btn-secondary flex-1">Cancel</button>
                            <button onClick={handleUpdateRole} className="btn-primary flex-1 flex items-center justify-center gap-2">
                                <Save size={18} /> Save Changes
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Delete Confirmation Modal */}
            {isDeleteModalOpen && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="glass-card max-w-sm w-full p-8 space-y-6 text-center">
                        <div className="mx-auto p-4 bg-red-500/20 rounded-full w-fit text-red-400">
                            <Trash2 size={32} />
                        </div>
                        <div>
                            <h3 className="text-xl font-bold">Delete Role?</h3>
                            <p className="text-premium-secondary text-sm mt-2">
                                Are you sure you want to delete <strong>{roleToDelete?.name}</strong>?
                                Users assigned to this role may lose their access.
                            </p>
                        </div>
                        <div className="flex gap-4">
                            <button onClick={() => setIsDeleteModalOpen(false)} className="btn-secondary flex-1">Cancel</button>
                            <button onClick={handleDeleteRole} className="btn-primary bg-red-500 border-red-500 hover:bg-red-600 flex-1">
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default RolesView;
