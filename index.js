require("dotenv").config();
const express = require('express');
const http = require("http");
const { neon } = require("@neondatabase/serverless");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const { Pool } = require('pg');

dotenv.config();

const app = express();
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
  });
  
  // Middleware to validate JWT
  const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization'];
  
    if (!token) return res.sendStatus(403);
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  };
  
  // Register a new user
  app.post('/register', async (req, res) => {
    const { email, password } = req.body;
  
    // Check if the email already exists
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      return res.status(400).json({ message: 'Email already exists' });
    }
  
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Insert the new user into the database
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hashedPassword]);
  
    res.status(201).json({ message: 'User registered successfully' });
  });
  
  // Login
  app.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    // Find the user in the database
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
  
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
  
    // Compare the password with the hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
  
    // Create a JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });
  
    res.json({ token });
  });
  
  // Protected route (requires JWT)
  app.get('/profile', authenticateJWT, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
  });
  
  // Start the server
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });