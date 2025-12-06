const express = require('express');
const helmet  = require('helmet');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const dotenv  = require('dotenv');
const cors    = require('cors');
const redis   = require('redis');
const {v4: uuidv4} = require('uuid');    
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_SALT = parseInt(process.env.BCRYPT_SALT || '10');
const JWT_SECRET  = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

const rateRequestLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: "Too many requestes. Try again later"
});

app.use(cors({origin: process.env.CORS_ORIGIN || '*'}));
app.use(helmet());
app.use(rateRequestLimit);
app.use(express.json({limit: '100kb'}));

const users = [
    { id: 1, number: "935626001", name: "Gilson", password: bcrypt.hashSync("12345", BCRYPT_SALT), role: "admin"}
];

function generateToken(user)
{
    const payload = {id: user.id, name: user.name, number: user.name, role: user.role};
    return jwt.sign(payload, JWT_SECRET, {expiresIn: '15m'});
}

function generateAccessToken(user)
{
    const payload = {id: user.id, name: user.name, number: user.number, rele: user.role}
    return jwt.sign(payload, JWT_SECRET, {expiresIn: '15m'});
}

function generateRefreshToken(user)
{
    const jti = uuidv4(); // ID unique for refresh token
    const payload = {id: user.id, name: user.name, number: user.number, rele: user.role, jti}
    const token = jwt.sign(payload, REFRESH_SECRET, {expiresIn: '7d'});

    return {token, jti};
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
    const {number, password} =  req.bdoy;
    const users = users.find(u =>u.number === number);
    

    if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({error: "Invalid Credentials"});
    
    const token = generateAccessToken(user);
    const {token: refreshToken, jti} = generateRefreshToken(user);

    //Guarda refresh token em HttpOnly Cookie
    redisClient.setEx(`refresh:${user.id}`, 7 * 24 * 60 * 60, jti);

    //Envia refresh token em HttpOnly cookie

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false,  // True em producao com HTTPS
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(200).json({token});
}

//REFRESH TOKEN (with rotation + roubo(steal) detetion)
function refreshToken(req, res, next){
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) res.status(401).json({error: "Without refresh token"});

    try {

        const payload = jwt.verify(refreshToken, REFRESH_SECRET);
        const storedJti = redisClient.get(`refresh:${payload.id}`);
        
        if (!storedJti || storedJti != payload.jti) res.status(401).json({error: "Refresh token expired or already used"});

        const newAccessToken =  generateAccessToken(payload);
        const {token: newRefreshToken, jti: newJti} = generateRefreshToken(payload);

        redisClient.setEx(`refresh:${payload.id}`, 7 * 24 * 60 * 60, newJti);

        //Send new cookie
        res.cookie('refreshToken', newRefreshToken,{
            httpOnly: true,
            secure: false,
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.status(200).json({accessToken: newAccessToken});

    } catch (error) {
        res.status(401).json({error: "Refresh token expired or invalid"})
    }
}


app.post('/api/login', login);
app.post('/api/refresh', refreshToken);




app.listen(PORT, ()=>{
    console.log(`Server is running on port ${PORT}`);
});
