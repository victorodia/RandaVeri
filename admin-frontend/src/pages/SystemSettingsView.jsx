import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../config';
import {
    Settings, Save, Globe, Palette, Type,
    Image as ImageIcon, CheckCircle2, RefreshCcw, Shield
} from 'lucide-react';
import Banner from '../components/Banner';

const SystemSettingsView = ({
    myPermissions = [],
    isSuperAdmin = false
}) => {
    const canManage = isSuperAdmin || myPermissions.includes('MANAGE_SETTINGS');

    const [config, setConfig] = useState({
        org_name: '',
        logo_url: '',
        primary_color: '#3B82F6',
        secondary_color: '#64748B'
    });
    const [loading, setLoading] = useState(false);
    const [banner, setBanner] = useState({ message: '', type: 'error' });

    const token = localStorage.getItem('token');
    const headers = { Authorization: `Bearer ${token}` };

    useEffect(() => {
        const fetchConfig = async () => {
            try {
                const res = await axios.get('http://localhost:8000/admin/config', { headers });
                setConfig(res.data);
            } catch (err) {
                console.error("Failed to fetch settings", err);
            }
        };
        fetchConfig();
    }, []);

    const handleSave = async (e) => {
        e.preventDefault();
        setLoading(true);
        setSaved(false);
        try {
            await axios.put('http://localhost:8000/admin/config', config, { headers });
            setBanner({ message: "System settings updated successfully", type: 'success' });
        } catch (err) {
            setBanner({ message: "Failed to save configuration", type: 'error' });
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="max-w-2xl mx-auto space-y-6 animate-in slide-in-from-bottom-4 duration-500">
            <Banner
                message={banner.message}
                type={banner.type}
                onClose={() => setBanner({ ...banner, message: '' })}
            />
            <div className="glass-card">
                <div className="flex items-center gap-3 mb-8 border-b border-premium-border pb-4">
                    <Settings className="text-premium-primary" size={28} />
                    <div>
                        <h2 className="text-2xl font-bold">White-Label Settings</h2>
                        <p className="text-premium-secondary text-sm">Customize the client-facing portal experience</p>
                    </div>
                </div>

                <form onSubmit={handleSave} className="space-y-6">
                    <div className="grid grid-cols-1 gap-6">
                        <div className="space-y-2">
                            <label className="flex items-center gap-2 text-sm font-medium text-premium-secondary">
                                <Type size={16} /> Organisation Name
                            </label>
                            <input
                                type="text"
                                className="input-field w-full"
                                value={config.org_name}
                                onChange={e => setConfig({ ...config, org_name: e.target.value })}
                                placeholder="e.g. Randaframes Global"
                            />
                        </div>

                        <div className="space-y-2">
                            <label className="flex items-center gap-2 text-sm font-medium text-premium-secondary">
                                <ImageIcon size={16} /> Logo URL
                            </label>
                            <input
                                type="text"
                                className="input-field w-full"
                                value={config.logo_url}
                                onChange={e => setConfig({ ...config, logo_url: e.target.value })}
                                placeholder="https://example.com/logo.png"
                            />
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <label className="flex items-center gap-2 text-sm font-medium text-premium-secondary">
                                    <Palette size={16} /> Primary Color
                                </label>
                                <div className="flex gap-2">
                                    <input
                                        type="color"
                                        className="h-10 w-10 bg-transparent cursor-pointer"
                                        value={config.primary_color}
                                        onChange={e => setConfig({ ...config, primary_color: e.target.value })}
                                    />
                                    <input
                                        type="text"
                                        className="input-field flex-1 text-sm font-mono uppercase"
                                        value={config.primary_color}
                                        onChange={e => setConfig({ ...config, primary_color: e.target.value })}
                                    />
                                </div>
                            </div>
                            <div className="space-y-2">
                                <label className="flex items-center gap-2 text-sm font-medium text-premium-secondary">
                                    <Globe size={16} /> Accent Color
                                </label>
                                <div className="flex gap-2">
                                    <input
                                        type="color"
                                        className="h-10 w-10 bg-transparent cursor-pointer"
                                        value={config.secondary_color}
                                        onChange={e => setConfig({ ...config, secondary_color: e.target.value })}
                                    />
                                    <input
                                        type="text"
                                        className="input-field flex-1 text-sm font-mono uppercase"
                                        value={config.secondary_color}
                                        onChange={e => setConfig({ ...config, secondary_color: e.target.value })}
                                    />
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="pt-6 flex items-center justify-between">
                        <div className="flex items-center gap-2 text-sm text-premium-accent">
                            <div className="flex items-center gap-2 text-sm text-premium-accent">
                            </div>
                        </div>
                        {canManage && (
                            <button
                                type="submit"
                                disabled={loading}
                                className="btn-primary flex items-center gap-2 px-8 min-w-[140px] justify-center"
                            >
                                {loading ? <RefreshCcw size={18} className="animate-spin" /> : <Save size={18} />}
                                Save Changes
                            </button>
                        )}
                    </div>
                </form>
            </div>

            <div className="p-4 bg-white/5 border border-white/10 rounded-xl">
                <p className="text-xs text-premium-secondary flex items-center gap-2">
                    <Shield size={14} /> Note: These settings instantly update the login and dashboard branding in the client-portal.
                </p>
            </div>
        </div>
    );
};

export default SystemSettingsView;
