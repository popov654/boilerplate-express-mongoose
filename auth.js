import { createHash, randomBytes } from 'crypto';
import crypto from 'crypto';
import fs from 'fs';
import mongoose from 'mongoose';
import User from './model/user.js';
import Session from './model/session.js';
import db from './db.js';

await db.connect();

const SECURE_AUTH_ENABLED = true;

const Auth = {
    register: async (req, res, next) => {
        const { username, password } = req.body
        if (password.length < 6) {
            return res.status(400).json({ error: "Password is shorter than 6 characters" })
        }
        let user = await User.findOne({ email: username });
        if (user) {
            return res.status(404).send({ error: `User ${username} already exists` });
        }
        const salt = randomBytes(10).toString('hex');
        const hashedPassword = createHash('sha256').update(password + salt).digest('hex') + ':' + salt;
        try {
            User.create({
                email: username,
                password: hashedPassword
            }).then(user =>
                res.status(200).json({
                    message: "User successfully created",
                    user
                })
            )
        } catch (err) {
            res.status(401).json({
                message: "User not successful created",
                error: err.message
            })
        }
    },

    login: async (req, res, next) => {
        let { username, password } = req.body;
        let result = false;
        if (username == null && SECURE_AUTH_ENABLED) {
            let token = null;
            if (req.headers['authorization-token']) {
                token = req.headers['authorization-token']
            }
            let credentials = secureLogin(token);
            username = credentials.username;
            password = credentials.password;
            if (username == null) {
                res.status(404).send({error: "User not found"});
                return false;
            }
        }
        try {
            let user = await User.findOne({ email: username });
            if (user) {
                const salt = user.password.split(':')[1];
                const hashedPassword = createHash('sha256').update(password + salt).digest('hex');
                result = user.password.split(':')[0] == hashedPassword;
                if (result) {
                    let session = await Session.create({
                        userId: user.id,
                        ip: req.ip
                    });
                    res.set('Authorization', session.id);
                    req.session = session;
                    if (next) next();
                    return true;
                } else {
                    res.status(404).send({error: "Incorrect password"});
                    return false;
                }
            } else {
                res.status(404).send({error: "User not found"});
                return false;
            }
            //console.log(user);
        } catch (error) {
            res.status(401).send({error: error.message});
            return false;
        }
    },
    
    doAuth: async (req, res, next) => {
        let sessionId = null;
        if (req.headers['authorization']) {
            sessionId = req.headers['authorization'].split(/\s+/).pop()
        }
        
        if (!sessionId && req.originalUrl != '/login') {
            res.status(401).send({error: "Unauthorized"});
        } else {
            let session = await Session.findOne({ _id: sessionId });
            if (session) {
                req.session = session;
                if (!req.user) {
                    req.user = await User.findOne({ _id: session.userId });
                }
                session.lastAccess = Date.now();
                await session.save();
                next();
            }
        }
    },

    isAuthorized: async (req) => {
        let sessionId = null;
        if (req.headers['authorization']) {
            sessionId = req.headers['authorization'].split(/\s+/).pop()
        }
        if (sessionId == null) return false;
        let session = await Session.findOne({ _id: sessionId });
        if (session != null && !req.user) {
            req.user = await User.findOne({ _id: session.userId });
        }
        return session != null;
    },
    
    logout: async (req) => {
        let ssid = req.query.ssid;
        let sessionId = null;
        if (req.headers['authorization']) {
            sessionId = req.headers['authorization'].split(/\s+/).pop()
        }
        if (sessionId == null || ssid == null || ssid != sessionId) return false;
        await Session.findByIdAndRemove(sessionId);
        return true;
    }
};

function secureLogin(token) {
    /*crypto.generateKeyPair('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    }, (err, publicKey, privateKey) => {
        console.log(publicKey);
        console.log(privateKey);
    });
    */

    let key = '';
    try {
        key = fs.readFileSync('privkey', 'utf8');
    } catch (err) {
        console.error(err);
    }

    let privateKey = crypto.createPrivateKey('-----BEGIN PRIVATE KEY-----\n' + key + '\n-----END PRIVATE KEY-----');

    let data = token;

    const decryptedData = crypto.privateDecrypt({
            key: privateKey,
            passphrase: '',
            padding: crypto.constants.RSA_OAEP_PADDING,
            oaepHash: "sha256"
        },
        Buffer.from(data, 'base64')
    );
    
    //console.log(decryptedData.toString());
    let credentials = decryptedData.toString().split(':');

    return { username: credentials[0], password: credentials[1] };
}

export default Auth;