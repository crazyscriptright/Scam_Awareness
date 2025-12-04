/**
 * Environment Configuration Loader for Scam Awareness Platform
 * Automatically loads the appropriate .env file based on NODE_ENV
 */

const path = require('path');
const dotenv = require('dotenv');

function loadEnvironment() {
  const env = process.env.NODE_ENV;
  
  console.log('🔧 [ENV_LOADER] Loading environment:', env || 'development');
  
  let envFile;
  
  switch (env) {
    case 'production':
      envFile = '.env.prod';
      break;
    default:
      envFile = '.env';
      break;
  }
  
  const envPath = path.resolve(__dirname, envFile);
  console.log('🔧 [ENV_LOADER] Loading env file:', envPath);
  
  const result = dotenv.config({ path: envPath });
  
  if (result.error) {
    console.error('❌ [ENV_ERROR] Failed to load environment file:', result.error.message);
    // Fallback to default .env
    console.log('🔄 [ENV_FALLBACK] Loading default .env file');
    dotenv.config();
  } else {
    console.log('✅ [ENV_SUCCESS] Environment loaded successfully');
  }
  
  // Log current configuration (without sensitive data)
  console.log('🔧 [ENV_CONFIG]', {
    environment: env || 'development',
    port: process.env.PORT || 5000,
    hasJwtSecret: !!process.env.JWT_SECRET,
    jwtExpiry: process.env.JWT_EXPIRY || '24h',
    hasDatabaseUrl: !!process.env.DATABASE_URL,
    hasRecaptchaSecret: !!process.env.RECAPTCHA_SECRET_KEY,
    hasNewsApiKey: !!process.env.REACT_APP_NEWS_API_KEY,
    allowedOrigins: process.env.ALLOWED_ORIGINS || 'Not set',
    nodeEnv: process.env.NODE_ENV || 'development'
  });
}

module.exports = { loadEnvironment };
