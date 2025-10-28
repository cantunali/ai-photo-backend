const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const cloudinary = require('cloudinary').v2;
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');
const admin = require('firebase-admin');
require('dotenv').config();

// Debug için - dotenv yüklendikten sonra
console.log('\n🔍 Environment Variables Check:');
console.log('CLOUD_NAME:', process.env.CLOUDINARY_CLOUD_NAME ? '✅ SET' : '❌ NOT SET');
console.log('API_KEY:', process.env.CLOUDINARY_API_KEY ? '✅ SET' : '❌ NOT SET');
console.log('API_SECRET:', process.env.CLOUDINARY_API_SECRET ? '✅ SET' : '❌ NOT SET');
console.log('MONGODB_URI:', process.env.MONGODB_URI ? '✅ SET' : '❌ NOT SET');
console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? '✅ SET' : '❌ NOT SET');
console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET ? '✅ SET' : '❌ NOT SET');
console.log('N8N_WEBHOOK_URL:', process.env.N8N_WEBHOOK_URL ? '✅ SET' : '❌ NOT SET');
console.log('');

// Firebase Admin SDK initialization
try {
  const serviceAccount = require('./serviceAccountKey.json');
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('✅ Firebase Admin initialized');
} catch (error) {
  console.log('⚠️  Firebase Admin not configured (password reset disabled)');
}

const User = require('./models/User');
const auth = require('./middleware/auth');
const checkUsageLimit = require('./middleware/checkUsageLimit');

const app = express();
const PORT = process.env.PORT || 3001;

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ai-photo-transform')
  .then(() => {
    console.log('✅ MongoDB Connected');
  })
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    console.log('⚠️  App will continue without database (limited functionality)');
  });

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// CORS configuration for production (Session cookie support)
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:5174', 
      'http://localhost:5175',
      'https://ai-photo-transform.netlify.app',
      'https://deft-queijadas-bdd0f6.netlify.app'
    ];
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // CRITICAL for sessions
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  exposedHeaders: ['Content-Type', 'Authorization', 'Set-Cookie'],
  optionsSuccessStatus: 200,
  maxAge: 86400 // 24 hours
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'ai-photo-transform-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Passport Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3001/api/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if user exists
      let user = await User.findOne({ uid: profile.id });
      
      if (!user) {
        // Create new user
        user = await User.create({
          uid: profile.id,
          email: profile.emails[0].value,
          displayName: profile.displayName,
          photoURL: profile.photos[0]?.value,
          provider: 'google',
          role: 'free',
          usage: {
            photosProcessed: 0,
            totalLimit: 3,
            lastResetDate: new Date()
          }
        });
        console.log('✅ New user created:', user.email);
      } else {
        // Update last login
        user.lastLogin = new Date();
        await user.save();
      }
      
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }
));

// Serialize user
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

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
    endpoints: ['/health', '/api/upload', '/api/process']
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

// ==================== AUTH ROUTES ====================

// Google OAuth Login
app.get('/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Google OAuth Callback
app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication
    const frontendURL = process.env.FRONTEND_URL || 'http://localhost:5173';
    res.redirect(`${frontendURL}/app?login=success`);
  }
);

// Get Current User
app.get('/api/auth/user', auth, (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      email: req.user.email,
      displayName: req.user.displayName,
      photoURL: req.user.photoURL,
      role: req.user.role,
      usage: {
        photosProcessed: req.user.usage.photosProcessed,
        totalLimit: req.user.usage.totalLimit,
        remaining: req.user.getRemainingPhotos(),
        nextResetDate: req.user.getNextResetDate(),
        daysUntilReset: req.user.getDaysUntilReset()
      },
      subscription: req.user.subscription
    }
  });
});

// Email/Password Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, displayName } = req.body;
    
    // Validation
    if (!email || !password || !displayName) {
      return res.status(400).json({ error: 'Email, şifre ve isim gereklidir' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Şifre en az 6 karakter olmalıdır' });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Bu email zaten kayıtlı' });
    }
    
    // Create user in Firebase Authentication
    let firebaseUser = null;
    try {
      firebaseUser = await admin.auth().createUser({
        email,
        password,
        displayName
      });
    } catch (firebaseError) {
      if (firebaseError.code !== 'auth/email-already-exists') {
        console.error('Firebase user creation error:', firebaseError);
      }
      // Continue anyway - create in MongoDB
    }
    
    // Create user in MongoDB
    const user = new User({
      uid: firebaseUser?.uid || `email_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      email,
      password, // Will be hashed by pre-save hook
      displayName,
      provider: 'email',
      role: 'free'
    });
    
    await user.save();
    
    // Login user automatically
    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Kayıt başarılı ancak giriş başarısız oldu' });
      }
      
      res.json({
        message: 'Kayıt başarılı',
        user: {
          id: user._id,
          email: user.email,
          displayName: user.displayName,
          photoURL: user.photoURL,
          role: user.role,
          usage: {
            photosProcessed: user.usage.photosProcessed,
            totalLimit: user.usage.totalLimit,
            remaining: user.getRemainingPhotos()
          },
          subscription: user.subscription
        }
      });
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Kayıt sırasında bir hata oluştu' });
  }
});

// Email/Password Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email ve şifre gereklidir' });
    }
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Email veya şifre hatalı' });
    }
    
    // Check provider
    if (user.provider !== 'email' && user.provider !== 'password') {
      return res.status(400).json({ error: 'Bu hesap farklı bir yöntemle oluşturulmuş (Google ile giriş yapın)' });
    }
    
    // Verify password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Email veya şifre hatalı' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Login user
    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Giriş başarısız oldu' });
      }
      
      res.json({
        message: 'Giriş başarılı',
        user: {
          id: user._id,
          email: user.email,
          displayName: user.displayName,
          photoURL: user.photoURL,
          role: user.role,
          usage: {
            photosProcessed: user.usage.photosProcessed,
            totalLimit: user.usage.totalLimit,
            remaining: user.getRemainingPhotos(),
            nextResetDate: user.getNextResetDate(),
            daysUntilReset: user.getDaysUntilReset()
          },
          subscription: user.subscription
        }
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Giriş sırasında bir hata oluştu' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    req.session.destroy();
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

// Forgot Password - Generate reset token
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email gerekli' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      // Güvenlik: email bulunmasa da başarı mesajı dönüyoruz
      return res.json({ 
        success: true, 
        message: 'Eğer hesap varsa, şifre sıfırlama emaili gönderildi'
      });
    }
    
    // Reset token oluştur (32 byte = 64 character hex)
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    
    // Token'ı ve son kullanma tarihini kaydet (1 saat)
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();
    
    // Reset linki oluştur (Frontend'de kullanılacak)
    const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password?token=${resetToken}`;
    
    console.log('✅ Password reset link generated for:', email);
    console.log('Reset link:', resetLink);
    
    // Email gönderme kodu buraya gelecek (şimdilik skip)
    // sendPasswordResetEmail(email, resetToken);
    
    res.json({ 
      success: true, 
      message: 'Eğer hesap varsa, şifre sıfırlama emaili gönderildi'
    });
    
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Bir hata oluştu' });
  }
});

// Reset Password - Validate token and set new password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token ve şifre gerekli' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Şifre en az 6 karakter olmalıdır' });
    }
    
    // Token'ı hash'le ve veritabanında ara
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: new Date() }
    });
    
    if (!user) {
      return res.status(400).json({ error: 'Geçersiz veya süresi dolmuş reset linki' });
    }
    
    // Yeni şifre belirle
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();
    
    console.log('✅ Password reset successful for:', user.email);
    
    res.json({ success: true, message: 'Şifre başarıyla değiştirildi' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Bir hata oluştu' });
  }
});

// Check Auth Status
app.get('/api/auth/status', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      authenticated: true,
      user: {
        id: req.user._id,
        email: req.user.email,
        displayName: req.user.displayName,
        photoURL: req.user.photoURL,
        role: req.user.role,
        usage: {
          photosProcessed: req.user.usage.photosProcessed,
          totalLimit: req.user.usage.totalLimit,
          remaining: req.user.getRemainingPhotos(),
          nextResetDate: req.user.getNextResetDate(),
          daysUntilReset: req.user.getDaysUntilReset()
        }
      }
    });
  } else {
    res.json({ authenticated: false });
  }
});

// Admin: Get all users
app.get('/api/admin/users', auth, async (req, res) => {
  try {
    // Only admin can access
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const users = await User.find({}, {
      password: 0, // Don't send password
      resetPasswordToken: 0,
      resetPasswordExpires: 0
    }).sort({ createdAt: -1 });

    res.json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Kullanıcılar getirilemedi' });
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

// Process with N8N and Cloudinary (Protected Route)
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
      return res.json({
        success: true,
        processedImageUrl: finalImageUrl,
        demo: true
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
    
    // Increment user's photo count
    await req.user.incrementPhotoCount();
    
    res.json({
      success: true,
      processedImageUrl: response.data.imageUrl || response.data.images?.[0]?.url || finalImageUrl,
      originalImageUrl: finalImageUrl,
      usage: {
        used: req.user.usage.photosProcessed,
        limit: req.user.usage.totalLimit,
        remaining: req.user.getRemainingPhotos(),
        nextResetDate: req.user.getNextResetDate(),
        daysUntilReset: req.user.getDaysUntilReset()
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
