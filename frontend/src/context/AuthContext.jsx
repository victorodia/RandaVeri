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
        await axios.post(`${API_BASE_URL}/register?username=${username}&email=${email}&password=${password}`);
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
        const formData = new URLSearchParams();
        formData.append('email', email);
        const response = await axios.post(`${API_BASE_URL}/forgot-password`, formData);
        return response.data;
    };

    const resetPassword = async (token, newPassword) => {
        const formData = new URLSearchParams();
        formData.append('token', token);
        formData.append('new_password', newPassword);
        const response = await axios.post(`${API_BASE_URL}/reset-password`, formData);
        return response.data;
    };

    useEffect(() => {
        fetchUser();
    }, []);

    return (
        <AuthContext.Provider value={{ user, login, register, logout, forgotPassword, resetPassword, fetchUser, loading }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
