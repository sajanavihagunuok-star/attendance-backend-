const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();

// CORS middleware added by script
require('./middleware/cors')(app);

// Logging CORS debug middleware
require('./middleware/log_and_headers')(app);

const corsOptions = {
  origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : ['http://localhost:3000'],
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json());

// simple health route
app.get('/api/health', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || 'development' }));

// mount API routes
const coursesRouter = require('./routes/courses');
app.use('/api/courses', coursesRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));

module.exports = app;


