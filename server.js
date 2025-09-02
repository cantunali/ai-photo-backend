const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware - BODY SIZE LIMIT ARTTIRILDI
app.use(cors());
app.use(express.json({ limit: '50mb' }));  // 50MB limit
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Memory storage for Railway (dosyaları memory'de tut)
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

// Upload endpoint
app.post('/api/upload', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Dosya yüklenmedi' });
    }
    
    // Base64'e çevir
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

// Process with N8N
app.post('/api/process', async (req, res) => {
  try {
    const { imageUrl, selections } = req.body;
    
    const webhookUrl = process.env.N8N_WEBHOOK_URL;
    
    if (!webhookUrl) {
      // Demo response
      return res.json({
        success: true,
        processedImageUrl: imageUrl,
        demo: true,
        message: 'N8N URL tanımlanmamış - Demo mod'
      });
    }
    
    const response = await axios.post(webhookUrl, {
      imageUrl,
      selections
    }, {
      timeout: 120000
    });
    
    res.json({
      success: true,
      processedImageUrl: response.data.imageUrl,
      originalRequest: response.data.originalRequest
    });
    
  } catch (error) {
    console.error('Process error:', error);
    res.status(500).json({ 
      error: 'İşlem hatası',
      details: error.message 
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});