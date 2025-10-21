const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'Token bulunamadı' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findOne({ uid: decoded.uid });
    
    if (!user) {
      return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Geçersiz token' });
  }
};

module.exports = auth;

