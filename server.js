const express = require('express');
const helmet  = require('helmet');
const jwt     = require('jsonwebtoken');
const dotenv  = require('dotenv');
const cors    = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const rateRequestLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: "Too many requestes. Try again later"
});

app.use(cors({origin: process.env.CORS_ORIGIN || '*'}));
app.use(helmet());
app.use(rateRequestLimit());
dotenv.config();

const PORT = process.env.PORT || 3000;
const BCRYPT_SALT = parseInt(process.env.BCRYPT_SALT || '10');
