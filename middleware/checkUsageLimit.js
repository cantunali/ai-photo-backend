const User = require('../models/User');

const checkUsageLimit = async (req, res, next) => {
  try {
    const user = req.user;
    
    // Admin'ler için limit yok
    if (user.role === 'admin') {
      return next();
    }
    
    // Aylık resetleme kontrolü
    const now = new Date();
    const lastReset = new Date(user.usage.lastResetDate);
    const daysSinceReset = (now - lastReset) / (1000 * 60 * 60 * 24);
    
    // 30 günden fazla geçmişse sıfırla
    if (daysSinceReset >= 30) {
      user.usage.photosProcessed = 0;
      user.usage.lastResetDate = now;
      await user.save();
    }
    
    // Limit kontrolü (Hem Free hem Premium kullanıcılar için)
    if (user.usage.photosProcessed >= user.usage.monthlyLimit) {
      const planType = user.role === 'premium' ? 'Premium' : 'Free';
      return res.status(403).json({
        error: 'Aylık limit aşıldı',
        message: `${planType} plan ile ayda ${user.usage.monthlyLimit} fotoğraf işleyebilirsiniz. Limit doldu!`,
        limitReached: true,
        usage: {
          used: user.usage.photosProcessed,
          limit: user.usage.monthlyLimit,
          resetDate: new Date(lastReset.getTime() + 30 * 24 * 60 * 60 * 1000)
        }
      });
    }
    
    next();
  } catch (error) {
    console.error('Usage limit check error:', error);
    res.status(500).json({ error: 'Limit kontrolünde hata oluştu' });
  }
};

module.exports = checkUsageLimit;
