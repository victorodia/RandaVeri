import React, { useState } from 'react';
import { Eye, EyeOff } from 'lucide-react';

const PasswordInput = ({ value, onChange, placeholder = "Password", className = "", required = false, name, id }) => {
    const [showPassword, setShowPassword] = useState(false);

    return (
        <div className="relative">
            <input
                type={showPassword ? "text" : "password"}
                className={`input-field w-full pr-10 ${className}`}
                placeholder={placeholder}
                value={value}
                onChange={onChange}
                required={required}
                name={name}
                id={id}
            />
            <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-premium-secondary hover:text-white transition-colors flex items-center justify-center p-1 rounded-full hover:bg-white/10"
                tabIndex="-1" // Prevent tabbing to this button before input
            >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
        </div>
    );
};

export default PasswordInput;
