//require("dotenv").config();
const express = require('express');
const http = require("http");
const { neon } = require("@neondatabase/serverless");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const PORT = 4000;
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
  
 //Server connected
 app.get('/', (req, res) => {
    res.status(200).json('Main page');
  })

  // Register a new user
  app.post('/register', async (req, res) => {
    const { email, password,empleado } = req.body;
  
    // Check if the email already exists
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    const intempleado=parseInt(empleado)
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Insert the new user into the database
    await pool.query('INSERT INTO usuarios (email, contrasena,empleado) VALUES ($1, $2, $3)', [email, hashedPassword, intempleado]);
  
    res.status(201).json({ message: 'User registered successfully' });
  });
  
  //Get all users
  app.get('/usuarios',async (req,res)=>{
    try{
    const result=await pool.query('SELECT * FROM usuarios');
    res.json(result.rows); 
    }catch(err) {
        console.error(err);
        res.status(500).json({ message: 'database error' });

    } 
  })

  // Login
  app.post('/login', async (req, res) => {
    console.log(req.body);
    const email = req.body.email;
    const password=req.body.password;
    //const email = req.params.email;
    
    //console.log(req.params.email);
    //const password=req.params.password;
  
    // Find the user in the database
    const result = await pool.query("SELECT * FROM usuarios WHERE email=$1", [email]);
    const user = result.rows[0];
  
    if (user==0) {
      return res.status(400).json({ message: 'Invalid email or password 2' });
    }
    // Compare the password with the hashed password
    const isMatch = await bcrypt.compare(password, user.contasena);
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
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
  
  module.exports = app;