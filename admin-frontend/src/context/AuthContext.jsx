import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';
import { API_BASE_URL } from '../config';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    const login = async (username, password) => {
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);

        const response = await axios.post(`${API_BASE_URL}/login`, formData);
        localStorage.setItem('token', response.data.access_token);

        // Fetch user profile and check platform access
        try {
            const userData = await fetchUser();
            if (!userData.is_platform_user) {
                logout();
                throw new Error('Access denied: Your account does not have admin portal access.');
            }
            return response.data;
        } catch (err) {
            logout();
            throw err;
        }
    };

    const fetchUser = async () => {
        const token = localStorage.getItem('token');
        if (!token) {
            setUser(null);
            setLoading(false);
            return null;
        }
        try {
            const response = await axios.get(`${API_BASE_URL}/me`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setUser(response.data);
            setLoading(false);
            return response.data;
        } catch (err) {
            localStorage.removeItem('token');
            setUser(null);
            setLoading(false);
            throw err;
        }
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
                console.error("Logout API failed", err);
            }
        }
    };

    useEffect(() => {
        fetchUser().catch(() => { });
    }, []);

    useEffect(() => {
        let logoUrl = user?.organisation?.logo_url;

        // Handle relative paths by prepending API_BASE_URL
        if (logoUrl && logoUrl.startsWith('/uploads')) {
            logoUrl = `${API_BASE_URL}${logoUrl}`;
        }

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
        <AuthContext.Provider value={{ user, login, logout, fetchUser, loading }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
