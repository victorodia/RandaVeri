import React from 'react';
import { Shield, CheckCircle, Globe } from 'lucide-react';

const VerificationSlip = ({ result, branding }) => {
    if (!result) return null;

    const data = result.data || result;

    return (
        <div id="verification-slip" className="bg-white text-black p-8 max-w-2xl mx-auto border-[12px] border-double border-premium-primary/20 relative overflow-hidden print:m-0 print:border-none">
            {/* Watermark */}
            <div className="absolute inset-0 flex items-center justify-center opacity-[0.03] pointer-events-none select-none rotate-[-35deg]">
                <span className="text-9xl font-black uppercase whitespace-nowrap">{branding.name}</span>
            </div>

            {/* Header */}
            <div className="flex justify-between items-start mb-10 pb-6 border-b-2 border-premium-primary/10 relative">
                <div className="flex items-center gap-4">
                    {branding.logoUrl ? (
                        <img src={branding.logoUrl} alt="Logo" className="h-16 w-16 object-contain" />
                    ) : (
                        <div className="h-16 w-16 bg-premium-primary text-white rounded-lg flex items-center justify-center font-bold text-2xl">
                            {branding.logoText}
                        </div>
                    )}
                    <div>
                        <h1 className="text-2xl font-black tracking-tight uppercase">{branding.name}</h1>
                        <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Official Verification Certificate</p>
                    </div>
                </div>
                <div className="text-right">
                    <div className="bg-premium-primary/10 text-premium-primary px-3 py-1 rounded-full text-[10px] font-black uppercase inline-flex items-center gap-1">
                        <Shield size={10} /> Authenticated
                    </div>
                    <p className="text-[10px] mt-2 text-gray-400 font-mono">ID: {data.transaction_id || '---'}</p>
                </div>
            </div>

            {/* Main Content */}
            <div className="grid grid-cols-12 gap-8 relative">
                {/* Photo */}
                <div className="col-span-4">
                    <div className="aspect-[3/4] rounded-lg border-2 border-gray-100 bg-gray-50 flex items-center justify-center overflow-hidden shadow-sm">
                        {data.image ? (
                            <img src={`data:image/jpeg;base64,${data.image}`} className="w-full h-full object-cover" alt="Subject" />
                        ) : (
                            <span className="text-gray-300 font-bold text-xs uppercase">No Photo</span>
                        )}
                    </div>
                    <div className="mt-4 p-3 bg-gray-50 rounded-lg text-center border border-gray-100">
                        <p className="text-[8px] font-bold text-gray-400 uppercase mb-1">Status</p>
                        <div className="text-emerald-600 font-black text-xs uppercase flex items-center justify-center gap-1">
                            <CheckCircle size={10} /> Verified
                        </div>
                    </div>
                </div>

                {/* Details */}
                <div className="col-span-8 space-y-6">
                    <section>
                        <h3 className="text-[10px] font-black text-premium-primary uppercase tracking-[0.2em] mb-3 border-b border-gray-100 pb-1">Subject Information</h3>
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <p className="text-[8px] font-bold text-gray-400 uppercase mb-0.5">Surname</p>
                                <p className="text-sm font-black uppercase">{data.lname || '---'}</p>
                            </div>
                            <div>
                                <p className="text-[8px] font-bold text-gray-400 uppercase mb-0.5">First Names</p>
                                <p className="text-sm font-black uppercase">{[data.fname, data.mname].filter(Boolean).join(' ') || '---'}</p>
                            </div>
                            <div>
                                <p className="text-[8px] font-bold text-gray-400 uppercase mb-0.5">Date of Birth</p>
                                <p className="text-sm font-black uppercase font-mono">{data.dob || '---'}</p>
                            </div>
                            <div>
                                <p className="text-[8px] font-bold text-gray-400 uppercase mb-0.5">Contact Number</p>
                                <p className="text-sm font-black uppercase font-mono">{data.phone || '---'}</p>
                            </div>
                        </div>
                    </section>

                    <section>
                        <h3 className="text-[10px] font-black text-premium-primary uppercase tracking-[0.2em] mb-3 border-b border-gray-100 pb-1">Geographical Data</h3>
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <p className="text-[8px] font-bold text-gray-400 uppercase mb-0.5">State of Origin</p>
                                <p className="text-xs font-bold uppercase">{data.stateOfOrigin || '---'}</p>
                            </div>
                            <div>
                                <p className="text-[8px] font-bold text-gray-400 uppercase mb-0.5">Local Govt Area</p>
                                <p className="text-xs font-bold uppercase">{data.lgaOfOrigin || '---'}</p>
                            </div>
                            <div className="col-span-2">
                                <p className="text-[8px] font-bold text-gray-400 uppercase mb-0.5">Residential Address</p>
                                <p className="text-xs font-bold uppercase leading-tight">{[data.residenceAdress, data.residenceTown, data.residenceLga, data.residenceState].filter(Boolean).join(', ') || '---'}</p>
                            </div>
                        </div>
                    </section>
                </div>
            </div>

            {/* Footer */}
            <div className="mt-12 pt-6 border-t border-gray-100 flex justify-between items-center relative">
                <div className="flex items-center gap-2">
                    <div className="h-8 w-8 rounded-full bg-gray-50 flex items-center justify-center border border-gray-100">
                        <Globe size={14} className="text-gray-300" />
                    </div>
                    <div>
                        <p className="text-[8px] font-bold text-gray-400 uppercase leading-none mb-1">Timestamp</p>
                        <p className="text-[9px] font-black uppercase font-mono">{new Date().toLocaleString()}</p>
                    </div>
                </div>
                <div className="text-right">
                    <p className="text-[8px] font-bold text-gray-400 uppercase leading-none mb-1">Generated By</p>
                    <p className="text-[9px] font-black uppercase tracking-widest">{branding.name} Security Portal</p>
                </div>
            </div>

            {/* Security Pattern */}
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-premium-primary via-premium-accent to-premium-primary"></div>
        </div>
    );
};

export default VerificationSlip;
