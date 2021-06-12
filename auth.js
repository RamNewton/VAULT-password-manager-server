const auth = require("./middleware/auth");
const bcrypt = require("bcrypt");
const express = require("express");
const router = express.Router();
const Joi = require("joi");
const passwordComplexity = require("joi-password-complexity");
const jwt = require("jsonwebtoken");
const db = require("./init_db");
const admin = require("firebase-admin");
const blackList = require("./blacklistToken");

const complexityOptions = {
    min: 6,
    max: 256,
    numeric: 1,
    lowerCase: 0,
    upperCase: 0,
    symbol: 0,
    requirementCount: 3,
};

const usersDb = db.collection("users");

router.post("/register", async (req, res) => {
    const { error } = validate_register(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    let user = usersDb.where("email", "==", req.body.email);
    user = await user.get();
    if (user.docs.length > 0) return res.status(400).send("This email id has already been registered");

    const salt = await bcrypt.genSalt(10);
    const hashed_password = await bcrypt.hash(req.body.password, salt);

    await usersDb.add({
        name: req.body.name,
        email: req.body.email,
        password: hashed_password,
    });
    res.status(200).send();
});

router.post("/login", async (req, res) => {
    const { error } = validate_login(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    let user = usersDb.where("email", "==", req.body.email);
    user = await user.get();
    if (user.docs.length == 0) return res.status(401).send("Invalid Email or Password");
    user = user.docs[0];

    const validPassword = await bcrypt.compare(req.body.password, user.data().password);
    if (!validPassword) return res.status(401).send("Invalid Email or Password");

    const token = generateAuthToken(user);
    // res.status(200).send(token);
    res.status(200)
        .cookie("token", token, { sameSite: "strict", path: "/", expires: new Date(new Date().getTime() + 1800 * 1000), httpOnly: true })
        .send();
});

router.post("/logout", async (req, res) => {
    const token = req.cookies.token;
    if (token) blackList.addToken(token);
    res.status(200).send();
});

router.get("/login_status", (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(200).send({ logged_in: false });
    if (blackList.tokenExists(token)) return res.status(200).send({ logged_in: false });
    try {
        const decoded = jwt.verify(token, process.env.jwtPrivateKey);
        const currentTime = Math.floor(+new Date() / 1000);
        if (decoded.exp < currentTime) return res.status(200).send({ logged_in: false });
        return res.status(200).send({ logged_in: true });
    } catch {
        return res.status(200).send({ logged_in: false });
    }
});

function generateAuthToken(user) {
    return jwt.sign({ email: user.data().email, _id: user.id }, process.env.jwtPrivateKey, { expiresIn: "0.5h" });
}

function validate_register(req) {
    const schema = Joi.object({
        name: Joi.string()
            .pattern(/[a-zA-z ]+/, "name")
            .min(3)
            .max(50),
        email: Joi.string().email().required().min(3).max(255),
        password: passwordComplexity(complexityOptions),
    });

    return schema.validate(req);
}

function validate_login(req) {
    const schema = Joi.object({
        email: Joi.string().email().required().min(3).max(255),
        password: Joi.string(),
    });

    return schema.validate(req);
}

module.exports = router;
