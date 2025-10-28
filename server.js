const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const cloudinary = require('cloudinary').v2;
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const { Resend } = require('resend');
require('dotenv').config();

// JWT Helper Functions
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_EXPIRES_IN = '30d';

const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
};

// Email Configuration
let transporter = null;
let resend = null;

const initializeEmailService = () => {
  if (process.env.EMAIL_SERVICE === 'resend') {
    // Resend
    resend = new Resend(process.env.RESEND_API_KEY);
    console.log('✅ Resend email service configured');
  } else if (process.env.EMAIL_SERVICE === 'gmail') {
    // Gmail with App Password
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });
    console.log('✅ Gmail email service configured');
  } else if (process.env.EMAIL_SERVICE === 'custom') {
    // Custom SMTP server
    transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT) || 587,
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      },
      connectionTimeout: 60000,
      greetingTimeout: 30000,
      socketTimeout: 60000
    });
    console.log('✅ Custom SMTP configured');
  } else {
    console.log('⚠️  Email service not configured - password reset emails will not be sent');
  }
};

// Initialize email service
initializeEmailService();

// Email sending function
const sendPasswordResetEmail = async (email, resetToken, displayName) => {
  const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password?token=${resetToken}`;

  try {
    if (resend) {
      // Use Resend
      console.log('📧 Sending email via Resend...');
      console.log('From:', process.env.EMAIL_FROM || 'onboarding@resend.dev');
      console.log('To:', email);
      
      const result = await resend.emails.send({
        from: process.env.EMAIL_FROM || 'onboarding@resend.dev',
        to: email,
        subject: 'Şifre Sıfırlama İsteği - AI Photo Transform',
        html: `
          <h2>Şifre Sıfırlama</h2>
          <p>Merhaba ${displayName},</p>
          <p>Şifrenizi sıfırlamak için aşağıdaki linke tıklayın:</p>
          <p>
            <a href="${resetLink}" style="background-color: #6366f1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
              Şifremi Sıfırla
            </a>
          </p>
          <p>Ya da bu linki tarayıcıya kopyala:</p>
          <p>${resetLink}</p>
          <p>Bu link 1 saat içinde geçerliliğini yitirecektir.</p>
          <p>Bu isteği siz yapmadıysanız, bu emaili görmezden gelebilirsiniz.</p>
          <br/>
          <p>AI Photo Transform Ekibi</p>
        `
      });
      
      console.log('📬 Resend API Response:', JSON.stringify(result, null, 2));
      
      if (result.error) {
        console.error('❌ Resend Error:', result.error);
        return false;
      }
      
      console.log(`✅ Password reset email sent to: ${email} (via Resend, ID: ${result.data?.id})`);
      return true;
    } else if (transporter) {
      // Use Nodemailer
      const mailOptions = {
        from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
        to: email,
        subject: 'Şifre Sıfırlama İsteği - AI Photo Transform',
        html: `
          <h2>Şifre Sıfırlama</h2>
          <p>Merhaba ${displayName},</p>
          <p>Şifrenizi sıfırlamak için aşağıdaki linke tıklayın:</p>
          <p>
            <a href="${resetLink}" style="background-color: #6366f1; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
              Şifremi Sıfırla
            </a>
          </p>
          <p>Ya da bu linki tarayıcıya kopyala:</p>
          <p>${resetLink}</p>
          <p>Bu link 1 saat içinde geçerliliğini yitirecektir.</p>
          <p>Bu isteği siz yapmadıysanız, bu emaili görmezden gelebilirsiniz.</p>
          <br/>
          <p>AI Photo Transform Ekibi</p>
        `
      };
      await transporter.sendMail(mailOptions);
      console.log(`✅ Password reset email sent to: ${email} (via SMTP)`);
      return true;
    } else {
      console.log('⚠️  Email service not configured, skipping email send');
      return true; // Don't fail, just skip
    }
  } catch (error) {
    console.error('❌ Error sending email:', error);
    return false;
  }
};

// Debug için - dotenv yüklendikten sonra
console.log('\n🔍 Environment Variables Check:');
console.log('CLOUD_NAME:', process.env.CLOUDINARY_CLOUD_NAME ? '✅ SET' : '❌ NOT SET');
console.log('API_KEY:', process.env.CLOUDINARY_API_KEY ? '✅ SET' : '❌ NOT SET');
console.log('API_SECRET:', process.env.CLOUDINARY_API_SECRET ? '✅ SET' : '❌ NOT SET');
console.log('MONGODB_URI:', process.env.MONGODB_URI ? '✅ SET' : '❌ NOT SET');
console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? '✅ SET' : '❌ NOT SET');
console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET ? '✅ SET' : '❌ NOT SET');
console.log('GOOGLE_CALLBACK_URL:', process.env.GOOGLE_CALLBACK_URL ? '✅ SET' : '❌ NOT SET');
console.log('FRONTEND_URL:', process.env.FRONTEND_URL ? '✅ SET' : '❌ NOT SET');
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
const authJWT = require('./middleware/authJWT');
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
app.use(cookieParser());

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'ai-photo-transform-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 30 * 24 * 60 * 60 // 30 days
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
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
  passport.authenticate('google', { failureRedirect: '/login', session: false }),
  (req, res) => {
    // Successful authentication - Generate JWT
    const token = generateToken(req.user._id);
    const frontendURL = process.env.FRONTEND_URL || 'https://ai-photo-transform.netlify.app';
    
    console.log('🔐 Google OAuth Callback - FRONTEND_URL:', frontendURL);
    console.log('✅ JWT Token generated for user:', req.user.email);
    
    // Redirect with token in URL (frontend will save to localStorage)
    res.redirect(`${frontendURL}/app?token=${token}`);
  }
);

// Check Auth Status (JWT)
app.get('/api/auth/status', async (req, res) => {
  try {
    // Get token from Authorization header, cookie, or x-auth-token header
    let token = null;
    
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.token) {
      token = req.cookies.token;
    } else if (req.headers['x-auth-token']) {
      token = req.headers['x-auth-token'];
    }
    
    if (!token) {
      return res.json({ authenticated: false });
    }
    
    // Verify token
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.json({ authenticated: false });
    }
    
    // Get user from database
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.json({ authenticated: false });
    }
    
    res.json({
      authenticated: true,
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
  } catch (error) {
    console.error('Auth status error:', error);
    res.json({ authenticated: false });
  }
});

// Get Current User
app.get('/api/auth/user', authJWT, (req, res) => {
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
    
    // Generate JWT token
    const token = generateToken(user._id);
    
    // Set JWT in cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    
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
    
    // Generate JWT token
    const token = generateToken(user._id);
    
    // Set JWT in cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    
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
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Giriş sırasında bir hata oluştu' });
  }
});

// Logout (JWT)
app.post('/api/auth/logout', (req, res) => {
  // Clear JWT cookie
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  });
  res.json({ success: true, message: 'Logged out successfully' });
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
    
    console.log('🔐 Reset Token Generated:');
    console.log('   Plain Token:', resetToken);
    console.log('   Hashed Token:', hashedToken);
    
    // Token'ı ve son kullanma tarihini kaydet (1 saat)
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();
    
    console.log('✅ Token saved to database for:', email);
    
    // Send reset email
    await sendPasswordResetEmail(email, resetToken, user.displayName);
    
    console.log('✅ Password reset token generated for:', email);
    
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
    
    console.log('🔍 Reset Password Request:');
    console.log('   Received Token:', token);
    console.log('   Hashed Token:', hashedToken);
    
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: new Date() }
    });
    
    console.log('   Found User:', user ? user.email : 'NOT FOUND');
    
    if (!user) {
      console.log('❌ Reset token not found or expired');
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
app.get('/api/admin/users', authJWT, async (req, res) => {
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

// Admin: Delete user
app.delete('/api/admin/users/:userId', authJWT, async (req, res) => {
  try {
    // Only admin can access
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId } = req.params;

    // Don't allow deleting yourself
    if (userId === req.user._id.toString()) {
      return res.status(400).json({ error: 'Kendi hesabınızı silemezsiniz' });
    }

    const deletedUser = await User.findByIdAndDelete(userId);

    if (!deletedUser) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    console.log(`✅ User deleted: ${deletedUser.email}`);

    res.json({
      success: true,
      message: 'Kullanıcı başarıyla silindi',
      user: deletedUser
    });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Kullanıcı silinirken hata oluştu' });
  }
});

// Admin: Update user role
app.patch('/api/admin/users/:userId', authJWT, async (req, res) => {
  try {
    // Only admin can access
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId } = req.params;
    const { role } = req.body;

    // Validate role
    if (!['free', 'premium', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Geçersiz role' });
    }

    // Don't allow changing yourself to non-admin
    if (userId === req.user._id.toString() && role !== 'admin') {
      return res.status(400).json({ error: 'Kendi admin rolünüzü değiştiremezsiniz' });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { role },
      { new: true }
    ).select('-password -resetPasswordToken -resetPasswordExpires');

    if (!updatedUser) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    console.log(`✅ User role updated: ${updatedUser.email} -> ${role}`);

    res.json({
      success: true,
      message: 'Kullanıcı rolü güncellendi',
      user: updatedUser
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Kullanıcı güncellenirken hata oluştu' });
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
app.post('/api/process', authJWT, checkUsageLimit, async (req, res) => {
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

// Test endpoint for Resend API Key
app.get('/api/test-resend', async (req, res) => {
  try {
    const apiKey = process.env.RESEND_API_KEY;
    console.log('🔑 RESEND_API_KEY exists:', !!apiKey);
    console.log('🔑 RESEND_API_KEY length:', apiKey ? apiKey.length : 0);
    console.log('🔑 RESEND_API_KEY starts with:', apiKey ? apiKey.substring(0, 5) : 'N/A');
    console.log('🔑 RESEND_API_KEY ends with:', apiKey ? apiKey.substring(apiKey.length - 5) : 'N/A');
    
    if (!resend) {
      return res.json({ error: 'Resend not initialized', apiKey: !!apiKey });
    }
    
    const result = await resend.emails.send({
      from: 'onboarding@resend.dev',
      to: 'delivered@resend.dev',
      subject: 'Test Email',
      html: '<p>Test</p>'
    });
    
    res.json({ success: true, result });
  } catch (error) {
    res.json({ error: error.message, stack: error.stack });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`N8N Webhook: ${process.env.N8N_WEBHOOK_URL || 'Not configured'}`);
  console.log(`Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME ? 'Configured' : 'Not configured'}`);
});
