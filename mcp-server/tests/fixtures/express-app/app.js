const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const userRoutes = require('./routes/users');

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

app.use('/users', userRoutes);

module.exports = app;
