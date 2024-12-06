const express = require("express");
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const userRoutes = require('./src/routes/userRoutes');
// const errorHandler = require("./middleware/errorHandler");
const dotenv = require('dotenv').config();
const app = express()
const db = require('./src/config/database');
const port = process.env.PORT || 5000
// const bodyParser = require('body-parser'); // Optional, but can be used

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Routes
app.use('/api/users', userRoutes);

// app.use(errorHandler)

app.listen(port)
