require('dotenv').config();
const express = require('express');
const session = require('express-session');
const massive = require('massive');
const authCtrl = require('./controllers/authController');

const app = express();

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(express.json());

massive( { 
    connectionString: CONNECTION_STRING,
    ssl: { rejectUnauthorized: false }    
} ).then(db => {
    app.set('db', db);
    console.log('Database Connected');
});

app.use(
    session({
        resave: true,
        saveUninitialized: false,
        secret: SESSION_SECRET
    })
);

app.post('/auth/register', authCtrl.register);
app.post('/auth/login', authCtrl.login);
app.get('/auth/logout', authCtrl.logout);

app.listen(SERVER_PORT, () => {
    console.log(`Server is online and listening on port ${SERVER_PORT}`);
});