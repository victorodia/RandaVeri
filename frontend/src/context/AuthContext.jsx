import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../config';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    const login = async (username, password, orgSlug = null) => {
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);
        if (orgSlug) {
            formData.append('org_slug', orgSlug);
        }

        const response = await axios.post(`${API_BASE_URL}/login`, formData);
        localStorage.setItem('token', response.data.access_token);
        await fetchUser();
        return response.data;
    };

    const register = async (username, email, password) => {
        await axios.post(`${API_BASE_URL}/register`, { username, email, password });
        await login(username, password);
    };

    const fetchUser = async () => {
        const token = localStorage.getItem('token');
        if (!token) {
            setUser(null);
            setLoading(false);
            return;
        }
        try {
            const response = await axios.get(`${API_BASE_URL}/me`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setUser(response.data);
        } catch (err) {
            localStorage.removeItem('token');
            setUser(null);
        }
        setLoading(false);
    };

    const logout = async () => {
        const token = localStorage.getItem('token');
        // Check local storage removal first to ensure immediate client-side logout
        localStorage.removeItem('token');
        setUser(null);

        if (token) {
            try {
                await axios.post(`${API_BASE_URL}/logout`, {}, {
                    headers: { Authorization: `Bearer ${token}` }
                });
            } catch (err) {
                console.error("Logout Log Failed", err);
            }
        }
    };

    const forgotPassword = async (email) => {
        const response = await axios.post(`${API_BASE_URL}/forgot-password`, { email });
        return response.data;
    };

    const resetPassword = async (token, newPassword) => {
        const response = await axios.post(`${API_BASE_URL}/reset-password`, {
            token: token,
            new_password: newPassword
        });
        return response.data;
    };

    useEffect(() => {
        fetchUser();
    }, []);

    useEffect(() => {
        let logoUrl = user?.organisation?.logo_url;

        // Fallback if logo is missing or is a known broken placeholder
        if (!logoUrl || logoUrl.includes('placeholder')) {
            logoUrl = '/logo.jpeg';
        }

        if (logoUrl) {
            let favicon = document.getElementById('favicon');
            const newFavicon = document.createElement('link');
            newFavicon.id = 'favicon';
            newFavicon.rel = 'icon';

            // Determine type based on extension
            if (logoUrl.toLowerCase().includes('.svg')) {
                newFavicon.type = 'image/svg+xml';
            } else if (logoUrl.toLowerCase().includes('.png')) {
                newFavicon.type = 'image/png';
            } else {
                newFavicon.type = 'image/jpeg';
            }

            // Add timestamp to bust cache
            newFavicon.href = `${logoUrl}${logoUrl.includes('?') ? '&' : '?'}v=${new Date().getTime()}`;

            if (favicon) {
                document.head.removeChild(favicon);
            }
            document.head.appendChild(newFavicon);
        }
    }, [user]);

    return (
        <AuthContext.Provider value={{ user, login, register, logout, forgotPassword, resetPassword, fetchUser, loading }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
