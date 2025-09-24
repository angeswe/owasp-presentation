import express from 'express';
import { UserModel } from '../models/User';
import { PostModel } from '../models/Post';

const router = express.Router();

// VULNERABILITY A01: Broken Access Control
// This route demonstrates various access control failures

// VULNERABILITY: Direct object reference without authorization
router.get('/user/:id', async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    // VULNERABLE: No check if the current user should access this user's data
    const user = await UserModel.findById(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // VULNERABLE: Returns sensitive data including password and API key
    res.json({
      vulnerability: 'A01 - Broken Access Control',
      description: 'Direct object reference allows access to any user data',
      user: user,
      explanation: 'Anyone can access any user\'s data by changing the ID in the URL'
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// VULNERABILITY: Admin panel accessible without proper authorization
router.get('/admin/users', async (req, res) => {
  try {
    // VULNERABLE: No authentication or role check
    const users = await UserModel.getAllUsers();

    res.json({
      vulnerability: 'A01 - Broken Access Control',
      description: 'Admin endpoint accessible without authentication',
      users: users,
      explanation: 'This admin endpoint is accessible to anyone without checking credentials'
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// VULNERABILITY: Forced browsing - accessing posts without permission
router.get('/post/:id', async (req, res) => {
  try {
    const postId = parseInt(req.params.id);

    // VULNERABLE: No check if post is private or if user has permission
    const post = await PostModel.findById(postId);

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    res.json({
      vulnerability: 'A01 - Broken Access Control',
      description: 'Access to private posts without authorization',
      post: post,
      explanation: 'Private posts can be accessed by guessing IDs, even if is_public is false'
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// VULNERABILITY: Function level access control bypass
router.put('/user/:id/role', async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { role } = req.body;

    // VULNERABLE: No authentication check and anyone can elevate privileges
    const success = await UserModel.updateUser(userId, { role });

    if (success) {
      res.json({
        vulnerability: 'A01 - Broken Access Control',
        description: 'Privilege escalation without authentication',
        message: `User ${userId} role updated to ${role}`,
        explanation: 'Anyone can change any user\'s role, including making themselves admin'
      });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// VULNERABILITY: Missing access control on sensitive operations
router.delete('/user/:id', async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    // VULNERABLE: No authorization - anyone can delete any user account
    // In a real app, this would require authentication and proper authorization

    res.json({
      vulnerability: 'A01 - Broken Access Control',
      description: 'Account deletion without authorization',
      message: `User ${userId} would be deleted`,
      explanation: 'Any user account can be deleted without authentication or ownership verification',
      note: 'This is a demo - actual deletion is not implemented'
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// VULNERABILITY: Bypassing access control through parameter modification
router.get('/posts/user/:userId', async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);

    // VULNERABLE: No check if current user can access another user's posts
    const posts = await PostModel.getPostsByUserId(userId);

    res.json({
      vulnerability: 'A01 - Broken Access Control',
      description: 'Access to other users\' posts without authorization',
      posts: posts,
      explanation: 'Any user can view any other user\'s posts by changing the userId parameter'
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// VULNERABILITY: Metadata manipulation
router.get('/metadata/:userId', async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);

    // VULNERABLE: Exposing metadata without proper access control
    const user = await UserModel.findById(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      vulnerability: 'A01 - Broken Access Control',
      description: 'Metadata exposure without authorization',
      metadata: {
        user_id: user.id,
        account_created: user.created_at,
        api_key_hint: user.api_key?.substring(0, 4) + '****',
        role: user.role
      },
      explanation: 'User metadata is exposed to unauthorized users'
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;