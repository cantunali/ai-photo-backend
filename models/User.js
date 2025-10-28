const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  uid: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: function() {
      return this.provider === 'email' || this.provider === 'password';
    }
  },
  displayName: {
    type: String,
    required: true
  },
  photoURL: {
    type: String,
    default: null
  },
  provider: {
    type: String,
    enum: ['email', 'google', 'password'],
    default: 'email'
  },
  role: {
    type: String,
    enum: ['free', 'premium', 'admin'],
    default: 'free'
  },
  subscription: {
    status: {
      type: String,
      enum: ['active', 'inactive', 'trial', 'cancelled'],
      default: 'inactive'
    },
    plan: {
      type: String,
      enum: ['free', 'monthly', 'yearly'],
      default: 'free'
    },
    startDate: {
      type: Date,
      default: null
    },
    endDate: {
      type: Date,
      default: null
    },
    stripeCustomerId: {
      type: String,
      default: null
    },
    stripeSubscriptionId: {
      type: String,
      default: null
    }
  },
  usage: {
    photosProcessed: {
      type: Number,
      default: 0
    },
    lastResetDate: {
      type: Date,
      default: Date.now
    },
    totalLimit: {
      type: Number,
      default: 3
    },
    isUnlimited: {
      type: Boolean,
      default: false
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  }
});

// Pre-save hook to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  if (this.provider === 'google') return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Helper methods
userSchema.methods.canProcessPhoto = function() {
  if (this.role === 'admin') return true;
  if (this.role === 'premium' && this.subscription.status === 'active') {
    const now = new Date();
    const lastReset = new Date(this.usage.lastResetDate);
    const daysSinceReset = Math.floor((now - lastReset) / (1000 * 60 * 60 * 24));
    
    if (daysSinceReset >= 30) {
      this.usage.photosProcessed = 0;
      this.usage.lastResetDate = now;
      this.usage.totalLimit = 30;
    }
    
    return this.usage.photosProcessed < this.usage.totalLimit;
  }
  
  return this.usage.photosProcessed < this.usage.totalLimit;
};

userSchema.methods.incrementPhotoCount = function() {
  this.usage.photosProcessed += 1;
  return this.save();
};

userSchema.methods.getRemainingPhotos = function() {
  if (this.role === 'admin') return 'Unlimited';
  const remaining = this.usage.totalLimit - this.usage.photosProcessed;
  return Math.max(0, remaining);
};

userSchema.methods.getNextResetDate = function() {
  if (this.role !== 'premium' || this.subscription.status !== 'active') {
    return null;
  }
  
  const lastReset = new Date(this.usage.lastResetDate);
  const nextReset = new Date(lastReset);
  nextReset.setDate(lastReset.getDate() + 30);
  return nextReset;
};

userSchema.methods.getDaysUntilReset = function() {
  const nextReset = this.getNextResetDate();
  if (!nextReset) return null;
  
  const now = new Date();
  const daysRemaining = Math.ceil((nextReset - now) / (1000 * 60 * 60 * 24));
  return Math.max(0, daysRemaining);
};

module.exports = mongoose.model('User', userSchema);
