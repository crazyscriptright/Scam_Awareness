const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET ;
const JWT_EXPIRY = process.env.JWT_EXPIRY ;

/**
 * Generate JWT token for authenticated user
 * @param {Object} user - User object from database
 * @returns {String} JWT token
 */
const generateToken = (user) => {
  return jwt.sign(
    { 
      id: user.user_id, 
      email: user.email, 
      userType: user.usertype,
      name: user.name,
      role: user.usertype === 1 ? 'admin' : user.usertype === 2 ? 'external' : 'user'
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
};

/**
 * Verify JWT token middleware
 * Adds decoded user info to req.user
 */
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided', error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired', error: 'Unauthorized' });
    }
    return res.status(401).json({ message: 'Invalid token', error: 'Unauthorized' });
  }
};

/**
 * Middleware to check if authenticated user is admin
 */
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.userType !== 1) {
    return res.status(403).json({ 
      message: 'Access denied. Admin privileges required.',
      error: 'Forbidden' 
    });
  }
  next();
};

/**
 * Middleware to check if authenticated user is external resource
 */
const requireExternal = (req, res, next) => {
  if (!req.user || req.user.userType !== 2) {
    return res.status(403).json({ 
      message: 'Access denied. External resource privileges required.',
      error: 'Forbidden' 
    });
  }
  next();
};

/**
 * Middleware to check if user is authenticated (any user type)
 */
const requireAuth = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ 
      message: 'Authentication required',
      error: 'Unauthorized' 
    });
  }
  next();
};

module.exports = { 
  generateToken, 
  verifyToken, 
  requireAdmin, 
  requireExternal,
  requireAuth
};
