// API Configuration for different environments
const API_CONFIG = {
  // Production API URL (your backend server)
  production: process.env.REACT_APP_API_URL || 'https://your-backend-api.com',
  
  // Development/Local API URL
  development: 'http://localhost:5000',
};

// Determine current environment
const isProduction = process.env.NODE_ENV === 'production';

// Export the appropriate base URL
export const API_BASE_URL = isProduction 
  ? API_CONFIG.production 
  : API_CONFIG.development;

// Helper to check if we're in production
export const isProductionEnv = () => isProduction;

// Export full API config
export default API_CONFIG;
