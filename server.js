
// Debug için
console.log('Environment Variables Check:');
console.log('CLOUD_NAME:', process.env.CLOUDINARY_CLOUD_NAME ? 'SET' : 'NOT SET');
console.log('API_KEY:', process.env.CLOUDINARY_API_KEY ? 'SET' : 'NOT SET');
console.log('API_SECRET:', process.env.CLOUDINARY_API_SECRET ? 'SET' : 'NOT SET');


const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const cloudinary = require('cloudinary').v2;
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const auth = require('./middleware/auth');
const checkUsageLimit = require('./middleware/checkUsageLimit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ai-photo-transform');

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// CORS configuration for production
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:5174', 
    'https://your-netlify-app.netlify.app', // Netlify URL'inizi buraya ekleyin
    'https://*.netlify.app' // Tüm Netlify alt domainleri
  ],
  credentials: true,
  optionsSuccessStatus: 200
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Memory storage for multer
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }
});

// Health check
app.get('/', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'AI Photo Transform API',
    endpoints: ['/health', '/api/upload', '/api/process', '/api/auth/verify', '/api/auth/user']
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

// Authentication endpoints
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { idToken, userData } = req.body;
    
    if (!idToken) {
      return res.status(400).json({ error: 'ID token gerekli' });
    }

    // Firebase ID token'ı decode et
    const decoded = jwt.decode(idToken);
    
    if (!decoded) {
      return res.status(401).json({ error: 'Geçersiz token' });
    }

    console.log('Decoded token:', {
      uid: decoded.user_id || decoded.uid,
      email: decoded.email,
      name: decoded.name,
      provider: decoded.firebase?.sign_in_provider
    });

    // Kullanıcıyı veritabanında bul veya oluştur
    const uid = decoded.user_id || decoded.uid || decoded.sub;
    let user = await User.findOne({ uid: uid });
    
    // Firebase provider'ı normalize et (password -> email)
    const firebaseProvider = decoded.firebase?.sign_in_provider || 'email';
    const normalizedProvider = firebaseProvider === 'password' ? 'email' : firebaseProvider;
    
    if (!user) {
      console.log('Creating new user:', uid);
      user = new User({
        uid: uid,
        email: decoded.email,
        displayName: decoded.name || decoded.email?.split('@')[0] || 'Kullanıcı',
        photoURL: decoded.picture || null,
        provider: normalizedProvider
      });
      await user.save();
      console.log('User created:', user._id);
    } else {
      console.log('User found, updating last login:', user._id);
      // Son giriş zamanını güncelle
      user.lastLogin = new Date();
      await user.save();
    }

    // JWT token oluştur
    const token = jwt.sign(
      { uid: user.uid, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        uid: user.uid,
        email: user.email,
        displayName: user.displayName,
        photoURL: user.photoURL,
        provider: user.provider
      }
    });
  } catch (error) {
    console.error('Auth verify error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ 
      error: 'Kimlik doğrulama hatası',
      details: error.message 
    });
  }
});

// Kullanıcı bilgilerini getir
app.get('/api/auth/user', auth, (req, res) => {
  res.json({
    success: true,
    user: {
      uid: req.user.uid,
      email: req.user.email,
      displayName: req.user.displayName,
      photoURL: req.user.photoURL,
      provider: req.user.provider,
      role: req.user.role,
      subscription: req.user.subscription,
      usage: {
        photosProcessed: req.user.usage.photosProcessed,
        monthlyLimit: req.user.usage.monthlyLimit,
        remaining: req.user.usage.monthlyLimit - req.user.usage.photosProcessed
      }
    }
  });
});

// Admin: Tüm kullanıcıları listele
app.get('/api/admin/users', async (req, res) => {
  try {
    const users = await User.find().select('-__v').sort({ createdAt: -1 });
    res.json({
      success: true,
      users,
      count: users.length
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Kullanıcılar getirilemedi' });
  }
});

// Premium'a yükseltme
app.post('/api/subscription/upgrade', auth, async (req, res) => {
  try {
    const { plan } = req.body; // 'monthly' veya 'yearly'
    
    if (!['monthly', 'yearly'].includes(plan)) {
      return res.status(400).json({ error: 'Geçersiz plan' });
    }
    
    const user = req.user;
    const now = new Date();
    const endDate = new Date(now);
    
    // Plan süresini hesapla
    if (plan === 'monthly') {
      endDate.setMonth(endDate.getMonth() + 1);
    } else {
      endDate.setFullYear(endDate.getFullYear() + 1);
    }
    
    // Kullanıcıyı premium yap
    user.role = 'premium';
    user.subscription = {
      status: 'active',
      plan: plan,
      startDate: now,
      endDate: endDate
    };
          user.usage.monthlyLimit = 25; // Premium: 25 photos/month
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Premium\'a yükseltildi!',
      user: {
        role: user.role,
        subscription: user.subscription,
        usage: user.usage
      }
    });
  } catch (error) {
    console.error('Upgrade error:', error);
    res.status(500).json({ error: 'Yükseltme hatası' });
  }
});

// Premium'dan free'ye düşürme (abonelik iptali)
app.post('/api/subscription/cancel', auth, async (req, res) => {
  try {
    const user = req.user;
    
    user.role = 'free';
    user.subscription = {
      status: 'cancelled',
      plan: 'free',
      startDate: null,
      endDate: null
    };
    user.usage.monthlyLimit = 5;
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Abonelik iptal edildi',
      user: {
        role: user.role,
        subscription: user.subscription,
        usage: user.usage
      }
    });
  } catch (error) {
    console.error('Cancel error:', error);
    res.status(500).json({ error: 'İptal hatası' });
  }
});

// Upload endpoint (artık kullanılmıyor ama bırakalım)
app.post('/api/upload', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Dosya yüklenmedi' });
    }
    
    const base64 = req.file.buffer.toString('base64');
    const dataUri = `data:${req.file.mimetype};base64,${base64}`;
    
    res.json({
      success: true,
      imageUrl: dataUri,
      size: req.file.size
    });
  } catch (error) {
    res.status(500).json({ error: 'Upload hatası' });
  }
});

// Process with N8N and Cloudinary (protected route with usage limit)
app.post('/api/process', auth, checkUsageLimit, async (req, res) => {
  try {
    const { imageUrl, selections } = req.body;
    console.log('Process request received');
    
    let finalImageUrl = imageUrl;
    
    // Base64'ü Cloudinary'ye yükle
    if (imageUrl && imageUrl.startsWith('data:')) {
      console.log('Uploading to Cloudinary...');
      
      const uploadResult = await cloudinary.uploader.upload(imageUrl, {
        folder: 'ai-photos-temp',
        resource_type: 'auto',
        tags: ['temp', `delete_${Date.now()}`]
      });
      
      finalImageUrl = uploadResult.secure_url;
      console.log('Image URL (temporary):', finalImageUrl);
      
      // 12 saat sonra sil
      setTimeout(() => {
        cloudinary.uploader.destroy(uploadResult.public_id).catch(err => {
          console.log('Auto-delete error (can be ignored):', err);
        });
      }, 12 * 60 * 60 * 1000);
    }
    
    const webhookUrl = process.env.N8N_WEBHOOK_URL;
    
    if (!webhookUrl) {
      console.log('N8N URL not configured - Demo mode');
      
      // Demo mode'da da sayacı artır
      req.user.usage.photosProcessed += 1;
      await req.user.save();
      
      return res.json({
        success: true,
        processedImageUrl: finalImageUrl,
        demo: true,
        usage: {
          used: req.user.usage.photosProcessed,
          limit: req.user.usage.monthlyLimit,
          remaining: req.user.usage.monthlyLimit - req.user.usage.photosProcessed
        }
      });
    }
    
    console.log('Sending to N8N with URL:', finalImageUrl);
    const response = await axios.post(webhookUrl, {
      imageUrl: finalImageUrl,
      selections
    }, {
      timeout: 120000,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    console.log('N8N response received');
    
    // Fotoğraf başarıyla işlendi, sayacı artır
    req.user.usage.photosProcessed += 1;
    await req.user.save();
    console.log(`User ${req.user.email} processed photo. Count: ${req.user.usage.photosProcessed}/${req.user.usage.monthlyLimit}`);
    
    res.json({
      success: true,
      processedImageUrl: response.data.imageUrl || response.data.images?.[0]?.url || finalImageUrl,
      originalImageUrl: finalImageUrl,
      usage: {
        used: req.user.usage.photosProcessed,
        limit: req.user.usage.monthlyLimit,
        remaining: req.user.usage.monthlyLimit - req.user.usage.photosProcessed
      }
    });
    
  } catch (error) {
    console.error('Process error:', error.message);
    res.status(500).json({ 
      error: 'İşlem hatası',
      details: error.message 
    });
  }
});

// Cleanup old images
const cleanupOldImages = async () => {
  try {
    const twelveHoursAgo = new Date(Date.now() - 12 * 60 * 60 * 1000);
    
    const result = await cloudinary.api.delete_resources_by_tag('temp', {
      created_at: `<${twelveHoursAgo.toISOString()}`
    });
    
    console.log('Cleanup completed:', result);
  } catch (error) {
    console.error('Cleanup error:', error);
  }
};

// Her 6 saatte bir temizlik yap
setInterval(cleanupOldImages, 6 * 60 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`N8N Webhook: ${process.env.N8N_WEBHOOK_URL || 'Not configured'}`);
  console.log(`Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME ? 'Configured' : 'Not configured'}`);
});