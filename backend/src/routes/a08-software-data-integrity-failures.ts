import express from 'express';
import multer from 'multer';
import path from 'path';

const router = express.Router();

// VULNERABILITY A08: Software and Data Integrity Failures

// Configure multer for file uploads (vulnerable configuration)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // VULNERABLE: No path validation
  },
  filename: (req, file, cb) => {
    // VULNERABLE: Using original filename without sanitization
    cb(null, file.originalname);
  }
});

const upload = multer({
  storage: storage,
  // VULNERABLE: No file type restrictions
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB - too large
  }
});

// VULNERABILITY: Unsigned/unverified file uploads
router.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  // VULNERABLE: No file integrity verification
  res.json({
    vulnerability: 'A08 - Software and Data Integrity Failures',
    description: 'Unsigned/unverified file upload',
    filename: req.file.filename,
    original_name: req.file.originalname,
    size: req.file.size,
    path: req.file.path,
    explanation: 'Uploaded files are not verified for integrity or signatures'
  });
});

// VULNERABILITY: Insecure deserialization simulation
router.post('/deserialize', (req, res) => {
  const { serialized_data } = req.body;

  try {
    // VULNERABLE: Unsafe deserialization
    // In a real app, this could be pickle, JSON.parse with functions, etc.
    const data = JSON.parse(serialized_data);

    res.json({
      vulnerability: 'A08 - Software and Data Integrity Failures',
      description: 'Insecure deserialization',
      deserialized: data,
      explanation: 'Deserializing untrusted data can lead to code execution'
    });
  } catch (error) {
    const err = error as Error;
    res.status(400).json({
      vulnerability: 'A08 - Software and Data Integrity Failures',
      error: 'Deserialization failed',
      message: err.message
    });
  }
});

// VULNERABILITY: Untrusted CDN/external resources
router.get('/external-resources', (req, res) => {
  res.json({
    vulnerability: 'A08 - Software and Data Integrity Failures',
    description: 'Loading resources from untrusted sources',
    external_scripts: [
      'http://untrusted-cdn.com/jquery.js',
      'https://suspicious-domain.com/app.js',
      'http://cdn.evil.com/bootstrap.css'
    ],
    explanation: 'Loading scripts from untrusted sources without integrity checks'
  });
});

// VULNERABILITY: No software integrity verification
router.get('/update-info', (req, res) => {
  res.json({
    vulnerability: 'A08 - Software and Data Integrity Failures',
    description: 'Software updates without integrity verification',
    update_info: {
      version: '2.0.1',
      download_url: 'http://updates.example.com/app-2.0.1.zip',
      checksum: null, // VULNERABLE: No checksum provided
      signature: null  // VULNERABLE: No digital signature
    },
    explanation: 'Software updates lack integrity verification mechanisms'
  });
});

// VULNERABILITY: CI/CD pipeline without security
router.post('/deploy', (req, res) => {
  const { package_name, version, source } = req.body;

  // VULNERABLE: No verification of deployment packages
  res.json({
    vulnerability: 'A08 - Software and Data Integrity Failures',
    description: 'Insecure CI/CD pipeline',
    deployment: {
      package: package_name,
      version: version,
      source: source,
      verified: false, // VULNERABLE: No verification
      signed: false    // VULNERABLE: Not signed
    },
    explanation: 'Deployment pipeline accepts unverified packages'
  });
});

export default router;