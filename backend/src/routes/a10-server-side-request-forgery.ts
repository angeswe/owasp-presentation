import express from 'express';
import axios from 'axios';

const router = express.Router();

// VULNERABILITY A10: Server-Side Request Forgery (SSRF)

// VULNERABILITY: Direct URL access without validation
router.post('/fetch-url', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    // VULNERABLE: No URL validation - can access internal resources
    const response = await axios.get(url, { timeout: 5000 });

    res.json({
      vulnerability: 'A10 - Server-Side Request Forgery (SSRF)',
      description: 'Unvalidated URL fetch',
      url: url,
      status: response.status,
      data: response.data,
      explanation: 'Try URLs like: http://localhost:22, http://169.254.169.254/latest/meta-data/'
    });
  } catch (error) {
    const err = error as Error;
    res.status(500).json({
      vulnerability: 'A10 - Server-Side Request Forgery (SSRF)',
      error: 'Request failed',
      url: url,
      message: err.message,
      explanation: 'Error reveals internal network structure'
    });
  }
});

// VULNERABILITY: Image/file processing from URL
router.post('/process-image', async (req, res) => {
  const { image_url } = req.body;

  if (!image_url) {
    return res.status(400).json({ error: 'Image URL is required' });
  }

  try {
    // VULNERABLE: Fetching arbitrary URLs for "image processing"
    const response = await axios.get(image_url, {
      timeout: 10000,
      maxRedirects: 5 // VULNERABLE: Follows redirects
    });

    res.json({
      vulnerability: 'A10 - Server-Side Request Forgery (SSRF)',
      description: 'SSRF via image processing',
      image_url: image_url,
      content_type: response.headers['content-type'],
      size: response.data.length,
      explanation: 'Image processing can be used to access internal services'
    });
  } catch (error) {
    const err = error as Error;
    res.status(500).json({
      vulnerability: 'A10 - Server-Side Request Forgery (SSRF)',
      error: 'Image processing failed',
      url: image_url,
      message: err.message
    });
  }
});

// VULNERABILITY: Webhook/callback URL without validation
router.post('/webhook', async (req, res) => {
  const { callback_url, data } = req.body;

  if (!callback_url) {
    return res.status(400).json({ error: 'Callback URL is required' });
  }

  try {
    // VULNERABLE: Posting to arbitrary URLs
    const response = await axios.post(callback_url, data, {
      timeout: 5000,
      headers: {
        'User-Agent': 'VulnerableApp/1.0',
        'X-Internal-Request': 'true' // VULNERABLE: Reveals internal origin
      }
    });

    res.json({
      vulnerability: 'A10 - Server-Side Request Forgery (SSRF)',
      description: 'SSRF via webhook callback',
      callback_url: callback_url,
      response_status: response.status,
      explanation: 'Webhooks can be used to make requests to internal services'
    });
  } catch (error) {
    const err = error as Error;
    res.status(500).json({
      vulnerability: 'A10 - Server-Side Request Forgery (SSRF)',
      error: 'Webhook failed',
      callback_url: callback_url,
      message: err.message
    });
  }
});

// VULNERABILITY: DNS resolution and port scanning
router.get('/check-service', async (req, res) => {
  const { host, port } = req.query;

  if (!host) {
    return res.status(400).json({ error: 'Host is required' });
  }

  try {
    // VULNERABLE: Can be used for internal network reconnaissance
    const url = `http://${host}:${port || 80}`;
    const response = await axios.get(url, {
      timeout: 3000,
      validateStatus: () => true // Accept any status code
    });

    res.json({
      vulnerability: 'A10 - Server-Side Request Forgery (SSRF)',
      description: 'Internal network reconnaissance',
      host: host,
      port: port || 80,
      status: response.status,
      reachable: true,
      explanation: 'Can be used to scan internal network and discover services'
    });
  } catch (error) {
    res.json({
      vulnerability: 'A10 - Server-Side Request Forgery (SSRF)',
      description: 'Internal network reconnaissance',
      host: host,
      port: port || 80,
      reachable: false,
      error: (error as any).code,
      explanation: 'Error codes reveal network topology'
    });
  }
});

// VULNERABILITY: Cloud metadata access
router.get('/metadata', async (req, res) => {
  try {
    // VULNERABLE: Accessing cloud metadata
    const metadataUrl = 'http://169.254.169.254/latest/meta-data/';
    const response = await axios.get(metadataUrl, { timeout: 2000 });

    res.json({
      vulnerability: 'A10 - Server-Side Request Forgery (SSRF)',
      description: 'Cloud metadata access',
      metadata_url: metadataUrl,
      data: response.data,
      explanation: 'SSRF can access cloud metadata containing sensitive information'
    });
  } catch (error) {
    res.json({
      vulnerability: 'A10 - Server-Side Request Forgery (SSRF)',
      description: 'Cloud metadata access attempt',
      note: 'Metadata service not accessible (not running on cloud)',
      explanation: 'In cloud environments, this could expose instance credentials'
    });
  }
});

export default router;