const checkUsageLimit = async (req, res, next) => {
  try {
    const user = req.user;

    // Check if user can process photo
    if (!user.canProcessPhoto()) {
      let message = '';
      
      if (user.role === 'free') {
        message = `Ücretsiz planınızda 3 fotoğraf işleyebilirsiniz. Yükseltmek için Premium'a geçin.`;
      } else if (user.role === 'premium') {
        const daysUntilReset = user.getDaysUntilReset();
        message = `Bu ay fotoğraf sınırınıza ulaştınız. ${daysUntilReset} gün sonra sıfırlanacak.`;
      }
      
      return res.status(403).json({ error: message });
    }

    next();
  } catch (error) {
    console.error('Usage check error:', error);
    res.status(500).json({ error: 'Bir hata oluştu' });
  }
};

module.exports = checkUsageLimit;
