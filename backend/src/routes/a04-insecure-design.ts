import express from 'express';
import { UserModel } from '../models/User';

const router = express.Router();

// VULNERABILITY A04: Insecure Design
// This demonstrates flawed security design patterns

// VULNERABILITY: Password reset without proper verification
router.post('/password-reset', async (req, res) => {
  const { username, new_password } = req.body;

  if (!username || !new_password) {
    return res.status(400).json({ error: 'Username and new password required' });
  }

  try {
    // VULNERABLE: No verification mechanism
    const user = await UserModel.findByUsername(username);
    if (user) {
      await UserModel.updateUser(user.id, { password: new_password });

      res.json({
        vulnerability: 'A04 - Insecure Design',
        description: 'Password reset without verification',
        message: `Password updated for ${username}`,
        explanation: 'Anyone can reset any user password without verification'
      });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// VULNERABILITY: Unlimited resource consumption
router.post('/unlimited-requests', (req, res) => {
  const { data } = req.body;

  // VULNERABLE: No rate limiting or resource constraints
  const result = [];
  for (let i = 0; i < 1000000; i++) {
    result.push(`Processing ${data} - ${i}`);
  }

  res.json({
    vulnerability: 'A04 - Insecure Design',
    description: 'No rate limiting or resource constraints',
    processed: result.length,
    explanation: 'This endpoint can consume unlimited server resources'
  });
});

// VULNERABILITY: Business logic bypass
router.post('/purchase', (req, res) => {
  const { item_id, quantity, user_id } = req.body;

  // VULNERABLE: No business logic validation
  const price = -10; // Negative price!
  const total = price * quantity;

  res.json({
    vulnerability: 'A04 - Insecure Design',
    description: 'Business logic bypass in purchase flow',
    item_id,
    quantity,
    user_id,
    price,
    total,
    explanation: 'Negative prices and quantities not validated'
  });
});

export default router;