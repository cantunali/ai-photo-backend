
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
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Middleware
app.use(cors());
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
    endpoints: ['/health', '/api/upload', '/api/process']
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
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

// Process with N8N and Cloudinary
app.post('/api/process', async (req, res) => {
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
    
    res.json({
      success: true,
      processedImageUrl: response.data.imageUrl || response.data.images?.[0]?.url || finalImageUrl,
      originalImageUrl: finalImageUrl
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