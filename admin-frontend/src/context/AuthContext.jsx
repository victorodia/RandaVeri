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

        const response = await axios.post('http://localhost:8000/login', formData);
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
            const response = await axios.get('http://localhost:8000/me', {
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
                await axios.post('http://localhost:8000/logout', {}, {
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

    return (
        <AuthContext.Provider value={{ user, login, logout, fetchUser, loading }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
