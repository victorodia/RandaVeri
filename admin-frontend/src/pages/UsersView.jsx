import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    Search, Edit2, Plus, CheckCircle, XCircle,
    Shield, CheckSquare, Square, Trash2, Building2
} from 'lucide-react';
import PasswordInput from '../components/PasswordInput';
import { useDialog } from '../context/DialogContext';

import { API_BASE_URL } from '../config';
const API = API_BASE_URL;

const BADGE_COLORS = {
    VIEW_ORG_WALLET: 'bg-status-blue/20 text-status-blue',
    VIEW_REVENUE: 'bg-status-emerald/20 text-status-emerald',
    VIEW_TRANSACTIONS: 'bg-status-purple/20 text-status-purple',
    VIEW_AUDIT_LOGS: 'bg-status-amber/20 text-status-amber',
    CREATE_USER: 'bg-status-emerald/20 text-status-emerald',
    EDIT_USER: 'bg-status-blue/20 text-status-blue',
    SUSPEND_USER: 'bg-status-orange/20 text-status-orange',
    DELETE_USER: 'bg-status-red/20 text-status-red',
    MANAGE_ROLES: 'bg-status-rose/20 text-status-rose',
    VIEW_REPORTS: 'bg-status-indigo/20 text-status-indigo',
    CREATE_ORGANISATION: 'bg-status-cyan/20 text-status-cyan',
    EDIT_ORGANISATION: 'bg-status-cyan/20 text-status-cyan', // Unified cyan/sky
    DELETE_ORGANISATION: 'bg-status-red/20 text-status-red',
    MANAGE_SUBSCRIPTION: 'bg-status-purple/20 text-status-purple',
    MANAGE_SETTINGS: 'bg-status-teal/20 text-status-teal',
    VIEW_TRANSACTIONS_ALT: 'bg-status-cyan/20 text-status-cyan',
};

const UsersView = ({
    users = [],
    onUpdateUser,
    onBulkAction,
    onToggleSuspension,
    myPermissions = [],
    isSuperAdmin = false
}) => {
    const canCreate = isSuperAdmin || myPermissions.includes('CREATE_USER');
    const canEdit = isSuperAdmin || myPermissions.includes('EDIT_USER');
    const canManageRoles = isSuperAdmin || myPermissions.includes('MANAGE_ROLES');
    const canSuspend = isSuperAdmin || myPermissions.includes('SUSPEND_USER');
    const canDelete = isSuperAdmin || myPermissions.includes('DELETE_USER');

    const [searchTerm, setSearchTerm] = useState('');
    const [selectedUsers, setSelectedUsers] = useState([]);
    const [organisations, setOrganisations] = useState([]);
    const [allPermissions, setAllPermissions] = useState([]);
    const [roles, setRoles] = useState([]);
    const [currentPage, setCurrentPage] = useState(1);
    const USERS_PER_PAGE = 10;

    const { showDialog, setDialogPassword } = useDialog();

    useEffect(() => {
        const token = localStorage.getItem('token');
        const headers = { Authorization: `Bearer ${token}` };

        Promise.all([
            axios.get(`${API}/admin/organisations`, { headers }),
            axios.get(`${API}/permissions`, { headers }),
            axios.get(`${API}/admin/roles`, { headers }),
        ]).then(([orgsRes, permsRes, rolesRes]) => {
            setOrganisations(orgsRes.data);
            setAllPermissions(permsRes.data);
            setRoles(rolesRes.data);
        }).catch(err => {
            console.error('Failed to load reference data', err);
        });
    }, []);

    const filteredUsers = (users || []).filter(u =>
        (u.username || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (u.email || '').toLowerCase().includes(searchTerm.toLowerCase())
    );

    const totalPages = Math.ceil(filteredUsers.length / USERS_PER_PAGE);
    const paginatedUsers = filteredUsers.slice(
        (currentPage - 1) * USERS_PER_PAGE,
        currentPage * USERS_PER_PAGE
    );

    useEffect(() => {
        setCurrentPage(1);
    }, [searchTerm]);

    const toggleSelect = (id) => {
        setSelectedUsers(prev =>
            prev.includes(id) ? prev.filter(uid => uid !== id) : [...prev, id]
        );
    };

    const toggleSelectAll = () => {
        setSelectedUsers(
            selectedUsers.length === filteredUsers.length ? [] : filteredUsers.map(u => u.id)
        );
    };

    // ── Modal State ─────────────────────────────────────────────
    const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
    const [isEditModalOpen, setIsEditModalOpen] = useState(false);
    const [editingUser, setEditingUser] = useState(null);

    const emptyNew = { username: '', email: '', telephone: '', password: '', permissions: [], role_id: null };
    const [newUser, setNewUser] = useState(emptyNew);

    // ── Parse existing role string → array ──────────────────────
    const parsePerms = (roleStr) => {
        if (!roleStr) return [];
        const parts = roleStr.split(',').map(s => s.trim()).filter(Boolean);
        const validKeys = allPermissions.map(p => p.key);
        return parts.filter(p => validKeys.includes(p));
    };

    const handleCreateUser = async () => {
        if (!newUser.role_id) {
            showDialog({
                type: 'error',
                title: 'Validation Error',
                message: 'Please select a role for the new user.'
            });
            return;
        }
        try {
            const token = localStorage.getItem('token');
            await axios.post(`${API}/org/users`, {
                username: newUser.username,
                email: newUser.email,
                telephone: newUser.telephone,
                password: newUser.password,
                role_id: newUser.role_id,
                permissions: [],
            }, { headers: { Authorization: `Bearer ${token}` } });

            showDialog({
                type: 'success',
                title: 'User Created',
                message: `User ${newUser.username} created successfully. A verification email has been sent to the email address and the user needs to be verified.`
            });
            setNewUser(emptyNew);
            setIsCreateModalOpen(false);
            setTimeout(() => { if (window.location) window.location.reload(); }, 1000);
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Creation Failed',
                message: err.response?.data?.detail || 'Registration failed'
            });
        }
    };

    const handleSavePermissions = async () => {
        if (!onUpdateUser) return;
        try {
            await onUpdateUser(editingUser.id, {
                role_id: editingUser.role_id,
                permissions: [],
            });
            setIsEditModalOpen(false);
            showDialog({
                type: 'success',
                title: 'Role Updated',
                message: 'User role updated successfully.'
            });
        } catch (err) {
            showDialog({
                type: 'error',
                title: 'Update Failed',
                message: 'Failed to update user role.'
            });
        }
    };

    const handleToggleUserSuspension = (user) => {
        const action = user.is_active ? 'Suspend' : 'Activate';
        showDialog({
            type: 'confirm',
            title: `${action} User`,
            message: `Are you sure you want to ${action.toLowerCase()} user "${user.username}"?`,
            confirmText: `Confirm ${action}`,
            isPasswordRequired: true,
            onConfirm: async (password) => {
                if (!password) {
                    showDialog({ type: 'error', title: 'Password Required', message: 'Admin password is required to perform this action.' });
                    return;
                }
                const success = await onToggleSuspension(user.id, password);
                if (success) {
                    showDialog({
                        type: 'success',
                        title: 'Status Updated',
                        message: `User "${user.username}" has been ${action === 'Suspend' ? 'suspended' : 'activated'}.`
                    });
                }
            }
        });
    };

    const PermissionPreview = ({ selected }) => (
        <div className="flex flex-wrap gap-2">
            {selected.length === 0 ? (
                <span className="text-xs text-premium-secondary italic">No permissions inherited</span>
            ) : (
                selected.map(key => {
                    const perm = allPermissions.find(p => p.key === key);
                    return (
                        <span key={key} title={perm?.description} className={`px-3 py-1 rounded-lg text-xs font-bold uppercase ${BADGE_COLORS[key] || 'bg-premium-overlay text-premium-text'}`}>
                            {perm?.label || key}
                        </span>
                    );
                })
            )}
        </div>
    );

    return (
        <div className="space-y-6 animate-in slide-in-from-right-4 duration-500">
            {/* Toolbar */}
            <div className="glass-card p-4 flex flex-wrap justify-between items-center gap-4 bg-premium-overlay">
                <div className="flex items-center gap-4">
                    <button onClick={toggleSelectAll} className="flex items-center gap-2 text-sm text-premium-secondary hover:text-premium-text">
                        {selectedUsers.length === filteredUsers.length ? <CheckSquare size={20} /> : <Square size={20} />}
                        Select All
                    </button>
                </div>
                <div className="flex items-center gap-4">
                    <div className="relative">
                        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-premium-secondary" />
                        <input
                            type="text"
                            placeholder="Search users..."
                            className="input-field pl-9 py-2 text-sm w-56"
                            value={searchTerm}
                            onChange={e => setSearchTerm(e.target.value)}
                        />
                    </div>
                    {canCreate && (
                        <button onClick={() => { setNewUser(emptyNew); setIsCreateModalOpen(true); }} className="btn-primary flex items-center gap-2 py-2 px-4 text-sm">
                            <Plus size={16} /> New User
                        </button>
                    )}
                </div>
            </div>

            {/* Table */}
            <div className="glass-card overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead className="bg-premium-overlay text-premium-secondary text-sm">
                            <tr>
                                <th className="px-6 py-4 text-left w-12"></th>
                                <th className="px-6 py-4 text-left">User</th>
                                <th className="px-6 py-4 text-left">Organisation</th>
                                <th className="px-6 py-4 text-left">Permissions</th>
                                <th className="px-6 py-4 text-left">Status</th>
                                <th className="px-6 py-4 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-premium-border">
                            {paginatedUsers.map(u => {
                                const isSystemRole = u.role === 'admin' || u.role?.includes('org_admin');
                                const userPerms = parsePerms(u.role);
                                return (
                                    <tr key={u.id} className={`hover:bg-premium-overlay transition-colors ${selectedUsers.includes(u.id) ? 'bg-premium-primary/5' : ''}`}>
                                        <td className="px-6 py-4">
                                            <button onClick={() => toggleSelect(u.id)}>
                                                {selectedUsers.includes(u.id) ? <CheckSquare size={18} className="text-premium-primary" /> : <Square size={18} className="text-premium-secondary" />}
                                            </button>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="font-semibold">{u.username}</div>
                                            <div className="text-xs text-premium-secondary">{u.email}</div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="flex flex-col">
                                                <div className="flex items-center gap-2">
                                                    <Building2 size={14} className="text-premium-secondary" />
                                                    <span className="text-sm font-medium">{u.organisation_name}</span>
                                                </div>
                                                {u.organisation_is_suspended && (
                                                    <span className="text-[9px] font-black text-status-red uppercase tracking-tighter mt-1 animate-pulse">Organisation Suspended</span>
                                                )}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 max-w-xs">
                                            {isSystemRole ? (
                                                <span className="flex items-center gap-1.5 text-status-amber text-xs font-bold">
                                                    <Shield size={13} />
                                                    {u.role === 'admin' ? 'Super Admin' : 'Organisation Admin'}
                                                </span>
                                            ) : u.role_id ? (
                                                <span className="flex items-center gap-1.5 text-premium-primary text-xs font-bold">
                                                    <Shield size={13} />
                                                    {roles.find(r => r.id === u.role_id)?.name || 'Role'}
                                                </span>
                                            ) : (
                                                <div className="flex flex-wrap gap-1">
                                                    {userPerms.map(key => (
                                                        <span key={key} className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${BADGE_COLORS[key] || 'bg-premium-overlay text-premium-text'}`}>
                                                            {allPermissions.find(p => p.key === key)?.label || key}
                                                        </span>
                                                    ))}
                                                    {canManageRoles && (
                                                        <button onClick={() => { setEditingUser({ ...u, permissions: userPerms, role_id: u.role_id }); setIsEditModalOpen(true); }} className="p-1 hover:bg-premium-overlay rounded">
                                                            <Edit2 size={12} className="text-premium-secondary" />
                                                        </button>
                                                    )}
                                                </div>
                                            )}
                                        </td>
                                        <td className="px-6 py-4">
                                            {!u.is_email_verified ? (
                                                <span className="px-2 py-0.5 rounded text-xs font-bold bg-status-amber/20 text-status-amber">
                                                    Pending Verification
                                                </span>
                                            ) : (
                                                <span className={`px-2 py-0.5 rounded text-xs font-bold ${u.is_active ? 'bg-status-emerald/20 text-status-emerald' : 'bg-status-red/20 text-status-red'}`}>
                                                    {u.is_active ? 'Active' : 'Suspended'}
                                                </span>
                                            )}
                                        </td>
                                        <td className="px-6 py-4 text-right">
                                            <div className="flex justify-end gap-2">
                                                {canSuspend && (
                                                    <button
                                                        onClick={() => handleToggleUserSuspension(u)}
                                                        className={`p-1.5 rounded-lg ${u.is_active ? 'hover:bg-status-red/20 text-status-red' : 'hover:bg-green-500/20 text-green-400'}`}
                                                        title={u.is_active ? 'Suspend' : 'Activate'}
                                                    >
                                                        {u.is_active ? <XCircle size={18} /> : <CheckCircle size={18} />}
                                                    </button>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <div className="flex items-center justify-between glass-card p-4 bg-premium-overlay">
                    <div className="text-sm text-premium-secondary">
                        Showing <span className="text-premium-text font-bold">{(currentPage - 1) * USERS_PER_PAGE + 1}</span> to <span className="text-premium-text font-bold">{Math.min(currentPage * USERS_PER_PAGE, filteredUsers.length)}</span> of <span className="text-premium-text font-bold">{filteredUsers.length}</span>
                    </div>
                    <div className="flex gap-2">
                        <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1} className="btn-secondary py-2 px-4 text-sm disabled:opacity-50">Previous</button>
                        <div className="flex items-center gap-1 px-4 text-sm font-bold">
                            <span className="text-premium-primary">{currentPage}</span>
                            <span className="text-premium-secondary">/</span>
                            <span>{totalPages}</span>
                        </div>
                        <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages} className="btn-primary py-2 px-4 text-sm disabled:opacity-50">Next</button>
                    </div>
                </div>
            )}

            {/* Modals */}
            {isCreateModalOpen && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="glass-card max-w-lg w-full p-8 space-y-6 max-h-[90vh] overflow-y-auto">
                        <h3 className="text-xl font-bold flex items-center gap-3"><Plus className="text-premium-primary" /> Create New User</h3>
                        <div className="space-y-4">
                            <input className="input-field w-full" placeholder="Username" value={newUser.username} onChange={e => setNewUser({ ...newUser, username: e.target.value })} />
                            <input className="input-field w-full" placeholder="Email" value={newUser.email} onChange={e => setNewUser({ ...newUser, email: e.target.value })} />
                            <input className="input-field w-full" placeholder="Telephone" value={newUser.telephone} onChange={e => setNewUser({ ...newUser, telephone: e.target.value })} />
                            <PasswordInput placeholder="Password" value={newUser.password} onChange={e => setNewUser({ ...newUser, password: e.target.value })} />
                            <select className="input-field w-full bg-premium-bg" value={newUser.role_id || ''} onChange={e => {
                                const rid = parseInt(e.target.value);
                                const role = roles.find(r => r.id === rid);
                                setNewUser({ ...newUser, role_id: rid, permissions: role?.permissions || [] });
                            }}>
                                <option value="" disabled>Select a Role...</option>
                                {roles.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                            </select>
                            <div className="space-y-3">
                                <label className="text-xs text-premium-secondary uppercase font-bold">Permissions</label>
                                <div className="border border-premium-border rounded-xl p-4 bg-premium-overlay">
                                    <PermissionPreview selected={newUser.permissions} />
                                </div>
                            </div>
                            <div className="flex gap-4 pt-2">
                                <button onClick={() => setIsCreateModalOpen(false)} className="btn-secondary flex-1">Cancel</button>
                                <button onClick={handleCreateUser} className="btn-primary flex-1">Create</button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {isEditModalOpen && editingUser && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="glass-card max-w-lg w-full p-8 space-y-6">
                        <h3 className="text-xl font-bold flex items-center gap-3"><Shield className="text-premium-primary" /> Edit User Role</h3>
                        <div className="space-y-4">
                            <select className="input-field w-full bg-premium-bg" value={editingUser.role_id || ''} onChange={e => {
                                const rid = parseInt(e.target.value);
                                const role = roles.find(r => r.id === rid);
                                setEditingUser({ ...editingUser, role_id: rid, permissions: role?.permissions || editingUser.permissions });
                            }}>
                                <option value="" disabled>Select a Role...</option>
                                {roles.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                            </select>
                            <div className="space-y-3">
                                <label className="text-xs text-premium-secondary uppercase font-bold">Permissions</label>
                                <div className="border border-premium-border rounded-xl p-4 bg-premium-overlay">
                                    <PermissionPreview selected={editingUser.permissions} />
                                </div>
                            </div>
                            <div className="flex gap-4 pt-2">
                                <button onClick={() => setIsEditModalOpen(false)} className="btn-secondary flex-1">Cancel</button>
                                <button onClick={handleSavePermissions} className="btn-primary flex-1">Save</button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default UsersView;
