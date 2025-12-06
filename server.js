const express = require('express');
const helmet  = require('helmet');
const jwt     = require('jsonwebtoken');
const dotenv  = require('dotenv');
const cors    = require('cors');
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_SALT = parseInt(process.env.BCRYPT_SALT || '10');
const JWT_SECRET  = process.env.JWT_SECRET;

const rateRequestLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: "Too many requestes. Try again later"
});

app.use(cors({origin: process.env.CORS_ORIGIN || '*'}));
app.use(helmet());
app.use(rateRequestLimit);
app.use(express.json({limit: '100kb'}));



function generateToken(user)
{
    const payload = {id: user.id, name: user.name, number: user.name, role: user.role};
    return jwt.sign(payload, JWT_SECRET, {expiresIn: '15m'});
}

function auth(req, res, next)
{
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) return res.status(401).json({error: 'Invalid request. Token is missing'});

    try{
        const payload =  jwt.verify(token, JWT_SECRET);
        req.user = payload;
        next();
    }catch(error)
    {
        res.status(401).json({error: "Token Invalid"});
    }
}

function login(req, res, next){
    res.status(200).json({message: "Hello Campeao do CodeFast Africell"});
}

app.post('/api/login', login);



app.listen(PORT, ()=>{
    console.log(`Server is running on port ${PORT}`);
});
