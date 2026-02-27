import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../config';

const BrandingContext = createContext();

export const BrandingProvider = ({ children }) => {
    const [branding, setBranding] = useState({
        name: "RandaFrames",
        logoText: "R",
        primaryColor: "#3B82F6",
        secondaryColor: "#64748B",
        logoUrl: "",
        orgSlug: localStorage.getItem('org_slug') || null
    });

    const loadOrganisation = async (slug) => {
        try {
            const res = await axios.get(`${API_BASE_URL}/organisations/${slug}/public`);
            const data = res.data;
            const updatedBranding = {
                name: data.name,
                logoText: data.name ? data.name[0] : "R",
                primaryColor: data.primary_color || "#3B82F6",
                secondaryColor: data.secondary_color || "#64748B",
                logoUrl: data.logo_url || "",
                orgSlug: slug
            };
            setBranding(updatedBranding);
            localStorage.setItem('org_slug', slug);

            // Apply CSS variables
            document.documentElement.style.setProperty('--premium-primary', data.primary_color || "#3B82F6");
            document.documentElement.style.setProperty('--premium-secondary', data.secondary_color || "#64748B");
            document.documentElement.style.setProperty('--premium-accent', data.secondary_color || "#64748B");
            return true;
        } catch (err) {
            console.error("Failed to load organisation", err);
            return false;
        }
    };
    const resetBranding = () => {
        const defaults = {
            name: "RandaFrames",
            logoText: "R",
            primaryColor: "#3B82F6",
            secondaryColor: "#64748B",
            logoUrl: "",
            orgSlug: null
        };
        setBranding(defaults);
        localStorage.removeItem('org_slug');

        document.documentElement.style.setProperty('--premium-primary', "#3B82F6");
        document.documentElement.style.setProperty('--premium-secondary', "#64748B");
        document.documentElement.style.setProperty('--premium-accent', "#64748B");
    };

    useEffect(() => {
        if (branding.orgSlug) {
            loadOrganisation(branding.orgSlug);
        }
    }, []);

    const updateBranding = (newBranding) => {
        setBranding({ ...branding, ...newBranding });
    };

    return (
        <BrandingContext.Provider value={{ branding, updateBranding, loadOrganisation, resetBranding }}>
            {children}
        </BrandingContext.Provider>
    );
};

export const useBranding = () => useContext(BrandingContext);
