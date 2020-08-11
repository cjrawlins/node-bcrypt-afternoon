const bcrypt = require('bcryptjs');

module.exports = {
    register: async (req, res, next) => {
        console.log("Register Called");
        let { username, password, isAdmin } = req.body;
        let db = req.app.get('db');
        let result = await db.get_user([username]);
        let exsistingUser = result[0];
        if (exsistingUser) {
            return res.status(409).send("Username taken");
        }
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(password, salt);
        let registeredUser = await db.register_user([isAdmin, username, hash]);
        let user = registeredUser[0];
        req.session.user = {
            isAdmin: user.is_admin,
            id: user.id,
            username: user.username
        }
        res.status(201).send(req.session.user);
    },
    login: async (req, res, next) => {
        console.log("Login Called");
        let { username, password } = req.body;
        let db = req.app.get('db');
        let foundUser = await db.get_user([username]);
        const user = foundUser[0];
        if (!user) {
            return res.status(401).send("User not found. Please register as a new user.");
        }
        const isAuthenticated = bcrypt.compareSync(password, user.hash)
        if (!isAuthenticated) {
            res.status(403).send("Password Inncorrect");
        }
        req.session.user = {
            isAdmin: user.is_admin,
            id: user.id,
            username: user.username
        }
        res.status(201).send(req.session.user);
    },
    logout: async (req, res) => {
        req.session.destroy();
        return res.sendStatus(200);
    }
}