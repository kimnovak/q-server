require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const axios = require('axios');
const app = express();

app.use(express.json());

let refreshTokens = [];

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    res.sendStatus(204);
});

app.post('/token', (req, res) => {
    const refreshToken = req.body.token;

    if (refreshToken == null) {
        return res.sendStatus(401);
    }
    if (!refreshTokens.includes(refreshToken)) {
        return res.sendStatus(403);
    }
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        const accessToken = generateAccessToken({userId: user.id})
        res.json({accessToken});
    });
});

app.post('/login', async (req, res) => {
    let users;
    try {
        const response = await axios.get('http://localhost:3001/users');
        users = response.data;
    } catch(e) {
        console.error(e)
        res.status(500).send('Error getting list of users');
    }
    
    if (!users) {
        return res.status(404).send('Cannot find user');
    }

    const user = users.find(user => user.username === req.body.username);
    if (user == null) {
        return res.status(404).send('Cannot find user');
    }
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const accessToken = generateAccessToken(user);
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
            refreshTokens.push(refreshToken);
            res.json({accessToken, refreshToken});
        } else {
            res.send('Not allowed')
        }

    } catch (e) {
        res.status(500).send();
    }
});

function generateAccessToken(user) {
    const accessToken = jwt.sign({userId: user.id}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '30m'})
    return accessToken;
}

app.listen(4000);