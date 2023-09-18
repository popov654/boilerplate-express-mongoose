import mongoose from 'mongoose';
import express from 'express';
import cors from 'cors';
import db from './db.js';
import auth from './auth.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { createHash, randomBytes } from 'crypto';

await db.connect();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({extended: false}));
app.use(express.static('public'));

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`CloudFave backend is running on port ${port}`);
    //var salt = randomBytes(10).toString('hex');
    //let hash = createHash('sha256').update('password' + salt).digest('hex') + ':' + salt;
    //console.log(hash);
});

app.get('/', (req, res) => {
    res.send({status: "OK"});
});

app.post('/register', (req, res) => {
    auth.register(req, res);
});

app.post('/login', async (req, res) => {
    let loggedIn = await auth.isAuthorized(req);
    if (!loggedIn) {
        loggedIn = await auth.login(req, res);
    }
    if (loggedIn) res.send({status: "OK", token: req.session.id});
});

app.get('/logout', async (req, res) => {
    let loggedIn = await auth.isAuthorized(req);
    if (loggedIn) {
        await auth.logout(req, res);
    }
    res.send({status: "OK"});
});

app.get('/api', [auth.doAuth], (req, res) => {
    res.send({status: "API test"});
});

app.get('/getAuthKey', (req, res) => {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    res.sendFile('pubkey', { root: path.join(__dirname) }, (err) => {
        if (err) {
            next(err);
        }
    });
});