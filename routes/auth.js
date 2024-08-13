// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../conf/db/models/user');
const verifyToken = require('../middlewares/auth');
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;

// Giriş səhifəsi
router.get('/login', (req, res) => {
  res.render('login');
});

// Qeydiyyat səhifəsi
router.get('/register', (req, res) => {
  res.render('register');
});

// Qeydiyyat
router.post('/register', async (req, res) => {
  try {
    const { userId, email, password } = req.body;

    const existingUser = await User.findOne({ $or: [{ userId }, { email }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User ID or Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      userId,
      email,
      password: hashedPassword,
    });

    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Giriş
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        message: "Authentication Failed"
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Authentication Failed"
      });
    }

    const jwtToken = jwt.sign(
      { email: user.email, userId: user.userId },
      JWT_SECRET,
      { expiresIn: "1m" }
    );

    res.cookie('token', jwtToken, { httpOnly: true });

    return res.status(200).json({
      accessToken: jwtToken,
      userId: user.userId,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Profil
router.get('/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.user.userId });
    if (!user) {
      return res.status(404).json({
        message: "User not found",
        success: false
      });
    }

    return res.status(200).json({
      message: `User ${user.email}`,
      success: true,
      data: user
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

module.exports = router;
