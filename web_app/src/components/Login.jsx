/**
 * Enhanced Login Component with MFA Support
 * Handles secure authentication flow including multi-factor authentication
 */

import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNotification } from '../context/NotificationContext';
import { authService } from '../services/authService';
import './Login.css';

const Login = ({ onLoginSuccess }) => {
  // Form states
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    mfaCode: '',
    rememberMe: false
  });
  
  // UI states
  const [showMfa, setShowMfa] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [isBlocked, setIsBlocked] = useState(false);
  const [blockTimeRemaining, setBlockTimeRemaining] = useState(0);

  // Password strength indicator
  const [passwordStrength, setPasswordStrength] = useState(null);
  const [showPasswordStrength, setShowPasswordStrength] = useState(false);

  // Form validation
  const [errors, setErrors] = useState({});
  const [touched, setTouched] = useState({});

  const { login, verifyMfa, requiresMfa } = useAuth();
  const { showNotification, showAuthError } = useNotification();

  // Handle rate limiting countdown
  useEffect(() => {
    let interval;
    if (isBlocked && blockTimeRemaining > 0) {
      interval = setInterval(() => {
        setBlockTimeRemaining(prev => {
          if (prev <= 1) {
            setIsBlocked(false);
            setLoginAttempts(0);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isBlocked, blockTimeRemaining]);

  // Sync MFA requirement from auth context
  useEffect(() => {
    setShowMfa(requiresMfa);
  }, [requiresMfa]);

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    const newValue = type === 'checkbox' ? checked : value;
    
    setFormData(prev => ({
      ...prev,
      [name]: newValue
    }));

    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }

    // Real-time password strength validation
    if (name === 'password' && value) {
      const strength = authService.validatePassword(value);
      setPasswordStrength(strength);
      setShowPasswordStrength(true);
    } else if (name === 'password' && !value) {
      setShowPasswordStrength(false);
    }

    // Mark field as touched
    setTouched(prev => ({
      ...prev,
      [name]: true
    }));
  };

  const validateForm = () => {
    const newErrors = {};

    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    }

    if (showMfa && !formData.mfaCode.trim()) {
      newErrors.mfaCode = 'MFA code is required';
    } else if (showMfa && formData.mfaCode.length !== 6) {
      newErrors.mfaCode = 'MFA code must be 6 digits';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (isBlocked) {
      showAuthError(`Too many failed attempts. Try again in ${blockTimeRemaining} seconds.`);
      return;
    }

    if (!validateForm()) {
      return;
    }

    setLoading(true);

    try {
      if (showMfa) {
        // Verify MFA code
        const result = await verifyMfa(formData.mfaCode);
        if (result.success) {
          showNotification('Login successful!', 'success');
          onLoginSuccess?.(result.user);
        }
      } else {
        // Initial login
        const credentials = {
          username: formData.username,
          password: formData.password
        };

        const result = await login(credentials);
        
        if (result.requiresMfa) {
          setShowMfa(true);
          showNotification('Please enter your MFA code', 'info');
        } else if (result.success) {
          showNotification('Login successful!', 'success');
          onLoginSuccess?.(result.user);
        }
      }
      
      // Reset form on success
      setFormData(prev => ({
        ...prev,
        password: '',
        mfaCode: ''
      }));
      setLoginAttempts(0);
      
    } catch (error) {
      console.error('Login error:', error);
      
      // Handle specific error cases
      if (error.status === 429) {
        const retryAfter = error.retryAfter || 300; // 5 minutes default
        setIsBlocked(true);
        setBlockTimeRemaining(retryAfter);
        showAuthError(`Too many attempts. Try again in ${retryAfter} seconds.`);
      } else if (error.status === 401) {
        setLoginAttempts(prev => prev + 1);
        if (loginAttempts >= 2) { // 3 attempts total
          setIsBlocked(true);
          setBlockTimeRemaining(300); // 5 minutes
          showAuthError('Account temporarily locked due to multiple failed attempts.');
        } else {
          showAuthError('Invalid username or password');
        }
      } else if (error.isNetworkError) {
        showAuthError('Network error. Please check your connection.');
      } else {
        showAuthError(error.message || 'Login failed. Please try again.');
      }
      
      // Clear sensitive fields on error
      setFormData(prev => ({
        ...prev,
        password: showMfa ? prev.password : '',
        mfaCode: ''
      }));
    } finally {
      setLoading(false);
    }
  };

  const handleBackToLogin = () => {
    setShowMfa(false);
    setFormData(prev => ({
      ...prev,
      mfaCode: ''
    }));
  };

  const formatTime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  const getPasswordStrengthColor = (strength) => {
    switch (strength?.strength) {
      case 'weak': return '#ff4757';
      case 'medium': return '#ffa502';
      case 'strong': return '#26de81';
      case 'very-strong': return '#00d084';
      default: return '#ddd';
    }
  };

  const getPasswordStrengthText = (strength) => {
    switch (strength?.strength) {
      case 'weak': return 'Weak';
      case 'medium': return 'Medium';
      case 'strong': return 'Strong';
      case 'very-strong': return 'Very Strong';
      default: return '';
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <div className="logo">
            <span className="logo-icon">🔒</span>
            <h1>SecureOps AI</h1>
          </div>
          <p className="login-subtitle">
            {showMfa ? 'Two-Factor Authentication' : 'Secure Access Portal'}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          {!showMfa ? (
            <>
              {/* Username Field */}
              <div className="form-group">
                <label htmlFor="username" className="form-label">
                  Username
                </label>
                <div className="input-group">
                  <span className="input-icon">👤</span>
                  <input
                    type="text"
                    id="username"
                    name="username"
                    value={formData.username}
                    onChange={handleInputChange}
                    className={`form-input ${errors.username ? 'error' : ''}`}
                    placeholder="Enter your username"
                    disabled={loading || isBlocked}
                    autoComplete="username"
                    autoFocus
                  />
                </div>
                {errors.username && (
                  <span className="error-message">{errors.username}</span>
                )}
              </div>

              {/* Password Field */}
              <div className="form-group">
                <label htmlFor="password" className="form-label">
                  Password
                </label>
                <div className="input-group">
                  <span className="input-icon">🔑</span>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    id="password"
                    name="password"
                    value={formData.password}
                    onChange={handleInputChange}
                    className={`form-input ${errors.password ? 'error' : ''}`}
                    placeholder="Enter your password"
                    disabled={loading || isBlocked}
                    autoComplete="current-password"
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                    disabled={loading || isBlocked}
                  >
                    {showPassword ? '🙈' : '👁️'}
                  </button>
                </div>
                {errors.password && (
                  <span className="error-message">{errors.password}</span>
                )}
                
                {/* Password Strength Indicator */}
                {showPasswordStrength && passwordStrength && (
                  <div className="password-strength">
                    <div className="strength-bar">
                      <div
                        className="strength-fill"
                        style={{
                          width: `${(passwordStrength.strength === 'weak' ? 25 : 
                                   passwordStrength.strength === 'medium' ? 50 : 
                                   passwordStrength.strength === 'strong' ? 75 : 100)}%`,
                          backgroundColor: getPasswordStrengthColor(passwordStrength)
                        }}
                      />
                    </div>
                    <span 
                      className="strength-text"
                      style={{ color: getPasswordStrengthColor(passwordStrength) }}
                    >
                      {getPasswordStrengthText(passwordStrength)}
                    </span>
                  </div>
                )}
              </div>

              {/* Remember Me */}
              <div className="form-group checkbox-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    name="rememberMe"
                    checked={formData.rememberMe}
                    onChange={handleInputChange}
                    disabled={loading || isBlocked}
                  />
                  <span className="checkbox-custom"></span>
                  Remember me for 30 days
                </label>
              </div>
            </>
          ) : (
            <>
              {/* MFA Code Field */}
              <div className="mfa-info">
                <span className="mfa-icon">📱</span>
                <p>Enter the 6-digit code from your authenticator app</p>
              </div>
              
              <div className="form-group">
                <label htmlFor="mfaCode" className="form-label">
                  Authentication Code
                </label>
                <div className="input-group">
                  <span className="input-icon">🔢</span>
                  <input
                    type="text"
                    id="mfaCode"
                    name="mfaCode"
                    value={formData.mfaCode}
                    onChange={handleInputChange}
                    className={`form-input mfa-input ${errors.mfaCode ? 'error' : ''}`}
                    placeholder="000000"
                    maxLength="6"
                    pattern="[0-9]{6}"
                    disabled={loading}
                    autoComplete="one-time-code"
                    autoFocus
                  />
                </div>
                {errors.mfaCode && (
                  <span className="error-message">{errors.mfaCode}</span>
                )}
              </div>

              <button
                type="button"
                className="back-button"
                onClick={handleBackToLogin}
                disabled={loading}
              >
                ← Back to Login
              </button>
            </>
          )}

          {/* Rate Limiting Warning */}
          {isBlocked && (
            <div className="rate-limit-warning">
              <span className="warning-icon">⏰</span>
              <p>Account locked for {formatTime(blockTimeRemaining)}</p>
            </div>
          )}

          {/* Failed Attempts Warning */}
          {loginAttempts > 0 && !isBlocked && (
            <div className="attempt-warning">
              <span className="warning-icon">⚠️</span>
              <p>{3 - loginAttempts} attempts remaining</p>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            className="login-button"
            disabled={loading || isBlocked}
          >
            {loading ? (
              <span className="loading-spinner">⏳</span>
            ) : showMfa ? (
              'Verify Code'
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        {/* Footer Links */}
        <div className="login-footer">
          <a href="/forgot-password" className="footer-link">
            Forgot your password?
          </a>
          <div className="security-notice">
            <span className="security-icon">🔐</span>
            <small>Your connection is secured with enterprise-grade encryption</small>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;