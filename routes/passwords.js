const auth = require("../middleware/auth");
const config = require("config");
const express = require("express");
const router = express.Router();
const Joi = require("joi");
const jwt = require("jsonwebtoken");
const db = require("../model/initDB");
const admin = require("firebase-admin");
const { encrypt, decrypt, getRandomKey } = require("../utils/encryption");
const passwordsDb = db.collection("passwords");

router.post("/create", auth, async (req, res) => {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const userPasswordsDb = passwordsDb.doc(req.user.email).collection("passwords");
    const accountsQuery = userPasswordsDb.where("accountName", "==", req.body.accountName);

    accounts = await accountsQuery.get();
    if (accounts.docs.length > 0) return res.status(400).send("An entry with this account name is already present.");

    let passwordBuffer = Buffer.from(req.body.password, "utf-8");
    let keyBuffer = Buffer.from(process.env.encryptKey, "utf-8");
    let encryptedMessageBuffer = encrypt(passwordBuffer, keyBuffer);

    await userPasswordsDb.add({
        accountName: req.body.accountName,
        username: req.body.username,
        password: encryptedMessageBuffer.toString("hex"),
    });

    passwordBuffer = null;
    encryptedMessageBuffer = null;
    keyBuffer = null;

    res.status(200).send();
});

router.get("/", auth, async (req, res) => {
    const userPasswordsDb = passwordsDb.doc(req.user.email).collection("passwords");
    let accounts = await userPasswordsDb.get();

    let keyBuffer = Buffer.from(process.env.encryptKey, "utf-8");

    try {
        if (accounts.size > 0) {
            accounts = accounts.docs.map((doc) => {
                let data = doc.data();
                let encryptedMessageBuffer = Buffer.from(data.password, "hex");
                let passwordBuffer = decrypt(encryptedMessageBuffer, keyBuffer);
                return { ...data, password: passwordBuffer.toString(), id: doc.id };
            });
        } else {
            accounts = [];
        }
    } catch (err) {
        console.log(err);
    }

    res.status(200).send(accounts);
});

router.put("/update/:id", auth, async (req, res) => {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const id = req.params.id;
    const userPasswordsDb = passwordsDb.doc(req.user.email).collection("passwords");
    const accountRef = userPasswordsDb.doc(id);
    let account = await accountRef.get();

    if (!account.exists) res.status(400).send("Entry for this account does not exist.");

    let passwordBuffer = Buffer.from(req.body.password, "utf-8");
    let keyBuffer = Buffer.from(process.env.encryptKey, "utf-8");
    let encryptedMessageBuffer = encrypt(passwordBuffer, keyBuffer);

    await accountRef.set({
        accountName: req.body.accountName,
        username: req.body.username,
        password: encryptedMessageBuffer.toString("hex"),
    });

    passwordBuffer = null;
    encryptedMessageBuffer = null;
    keyBuffer = null;

    res.status(200).send();
});

router.delete("/delete/:id", auth, async (req, res) => {
    // const { error } = validateDelete(req.body);
    // if (error) return res.status(400).send(error.details[0].message);
    const passwordsRef = passwordsDb.doc(req.user.email).collection("passwords");
    const accountRef = passwordsRef.doc(req.params.id);
    let account = await accountRef.get();

    if (!account.exists) res.status(400).send("Entry for this account does not exist.");

    await accountRef.delete();
    res.status(200).send();
});

function validate(req) {
    const schema = Joi.object({
        accountName: Joi.string().required().min(2).max(255),
        username: Joi.string().allow("").max(255),
        password: Joi.string().required(),
    });

    return schema.validate(req);
}

module.exports = router;
