require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Sequelize, DataTypes } = require('sequelize');
const { v4: uuidv4 } = require('uuid');

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: './database.sqlite'
  });

(async () => {
    try {
      sequelize.authenticate();
      await sequelize.sync();
      console.log('Connection has been established successfully.');
    } catch (error) {
      console.error('Unable to connect to the database:', error);
    }
})();

const app = express();

app.use(express.json());

const User = sequelize.define("user", {
    id: {
        type: DataTypes.UUID,
        allowNull: false,
        primaryKey: true, 
    },
    username: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    password: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    role: {
        type: DataTypes.TEXT,
        defaultValue: 'user',
    },        
});

const Purchase = sequelize.define('purchase', {
    id: {
        type: DataTypes.UUID,
        allowNull: false,
        primaryKey: true, 
    },
    userId: {
        type: DataTypes.UUID,
        allowNull: false,
    },
    products: {
        type: DataTypes.JSON,
    }
})

app.post('/users', async (req, res) => {
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        await User.create({
            id: uuidv4(),
            username: req.body.username,
            password: hashedPassword,
        });
        res.status(201).send();
    } catch (e) {
        console.log(e)
        res.status(500).send();
    }
})

app.post('/purchases', authenticateToken, async (req, res) => {
    try {
        await Purchase.create({
            id: uuidv4(),
            userId: req.userId,
            products: req.body.products,
        })
    } catch(e) {
        console.log(e);
    }
})

app.get('/purchases', authenticateToken, async (req, res) => {
    try {
        const purchases = await Purchase.findAll({where: {userId: req.userId}});

        res.json(purchases);
    } catch (e) {
        console.log(e);
        res.sendStatus(500);
    }
});

app.get('/users', async (req, res) => {
    try {
        const users = await User.findAll();
        res.json(users);
    } catch (e) {
        console.log(e);
        res.sendStatus(500);
    }
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.sendStatus(401);
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        console.log({user})
        req.userId = user.userId ?? user.user;
        next();
    });
}

app.listen(3001);