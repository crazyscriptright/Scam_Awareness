// JWT Token Management Utilities

const TOKEN_KEY = 'scam_awareness_token';
const USER_KEY = 'scam_awareness_user';

/**
 * Store JWT token in localStorage
 * @param {string} token - JWT token from backend
 */
export const setToken = (token) => {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  }
};

/**
 * Get JWT token from localStorage
 * @returns {string|null} JWT token or null
 */
export const getToken = () => {
  return localStorage.getItem(TOKEN_KEY);
};

/**
 * Remove JWT token from localStorage
 */
export const removeToken = () => {
  localStorage.removeItem(TOKEN_KEY);
};

/**
 * Store user data in localStorage
 * @param {object} user - User data from backend
 */
export const setUser = (user) => {
  if (user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }
};

/**
 * Get user data from localStorage
 * @returns {object|null} User object or null
 */
export const getUser = () => {
  const user = localStorage.getItem(USER_KEY);
  return user ? JSON.parse(user) : null;
};

/**
 * Remove user data from localStorage
 */
export const removeUser = () => {
  localStorage.removeItem(USER_KEY);
};

/**
 * Clear all auth data (token + user)
 */
export const clearAuth = () => {
  removeToken();
  removeUser();
};

/**
 * Check if user is authenticated (has valid token)
 * @returns {boolean}
 */
export const isAuthenticated = () => {
  const token = getToken();
  if (!token) return false;
  
  try {
    // Decode JWT to check expiration (basic check)
    const payload = JSON.parse(atob(token.split('.')[1]));
    const expiry = payload.exp * 1000; // Convert to milliseconds
    
    if (Date.now() >= expiry) {
      // Token expired, clear it
      clearAuth();
      return false;
    }
    
    return true;
  } catch (error) {
    // Invalid token format
    clearAuth();
    return false;
  }
};

/**
 * Get user role from token
 * @returns {string|null} User role or null
 */
export const getUserRole = () => {
  const token = getToken();
  if (!token) return null;
  
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.role || null;
  } catch (error) {
    return null;
  }
};

/**
 * Check if token is about to expire (within 5 minutes)
 * @returns {boolean}
 */
export const isTokenExpiringSoon = () => {
  const token = getToken();
  if (!token) return false;
  
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    const expiry = payload.exp * 1000;
    const fiveMinutes = 5 * 60 * 1000;
    
    return (expiry - Date.now()) < fiveMinutes;
  } catch (error) {
    return false;
  }
};
