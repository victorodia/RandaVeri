import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useBranding } from '../context/BrandingContext';
import { useAuth } from '../context/AuthContext';
import { Building2, ArrowRight } from 'lucide-react';
import Banner from '../components/Banner';

const OrgEntrance = () => {
    const [slug, setSlug] = useState('');
    const [error, setError] = useState('');
    const [bannerType, setBannerType] = useState('error');
    const [loading, setLoading] = useState(false);
    const { loadOrganisation, resetBranding } = useBranding();
    const { user } = useAuth();
    const navigate = useNavigate();

    React.useEffect(() => {
        resetBranding();
    }, []);


    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!slug) return;

        setLoading(true);
        setError('');
        const success = await loadOrganisation(slug);
        if (success) {
            navigate('/login');
        } else {
            setBannerType('error');
            setError('Organisation not found. Please check the ID and try again.');
        }
        setLoading(false);
    };

    return (
        <div className="min-h-screen bg-[#0D0F12] text-white flex items-center justify-center p-4 relative overflow-hidden">
            <Banner message={error} type={bannerType} onClose={() => setError('')} />

            <div className="absolute top-0 left-0 w-full h-full premium-mesh opacity-30"></div>

            <div className="bg-[#1A1D23]/60 backdrop-blur-md border border-[#2E343D] rounded-xl shadow-xl max-w-md w-full p-8 relative z-10 animate-in fade-in zoom-in duration-500">
                <div className="flex flex-col items-center mb-8">
                    <div className="h-16 w-16 premium-gradient rounded-2xl flex items-center justify-center mb-4 shadow-2xl">
                        <Building2 size={32} className="text-white" />
                    </div>
                    <h1 className="text-3xl font-bold tracking-tight text-white">Access Portal</h1>
                    <p className="text-[#64748B] mt-2">Enter your organisation's unique ID to continue</p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label className="text-sm font-bold text-[#64748B] uppercase tracking-widest mb-2 block">
                            Organisation ID
                        </label>
                        <input
                            type="text"
                            className="bg-[#0D0F12] border border-[#2E343D] rounded-lg py-2 px-4 focus:outline-none focus:border-[#3B82F6] transition-colors text-white w-full h-12 text-lg text-center font-mono uppercase tracking-[0.2em]"
                            placeholder="e.g. DEFAULT"
                            value={slug}
                            onChange={(e) => setSlug(e.target.value)}
                            autoFocus
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading || !slug}
                        className="bg-[#3B82F6] hover:bg-[#3B82F6]/80 text-white font-medium rounded-lg transition-all duration-200 disabled:opacity-50 w-full py-4 flex items-center justify-center gap-2 group"
                    >
                        {loading ? 'Verifying...' : (
                            <>
                                Continue to Workspace <ArrowRight size={20} className="group-hover:translate-x-1 transition-transform" />
                            </>
                        )}
                    </button>
                </form>

                <div className="mt-8 pt-6 border-t border-[#2E343D] text-center">
                    <p className="text-xs text-[#64748B]">
                        Don't have an Organisation ID? Contact your system administrator.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default OrgEntrance;
