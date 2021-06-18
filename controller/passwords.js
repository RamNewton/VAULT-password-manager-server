const Joi = require("joi");
const Password = require("../model/user");
const { encrypt, decrypt } = require("../utils/encryption");
const asyncHandler = require("../middleware/asyncHandler");

const validate = (data) => {
    const schema = Joi.object({
        accountName: Joi.string().required().min(2).max(255),
        username: Joi.string().allow("").max(255),
        password: Joi.string().required(),
    });

    return schema.validate(data);
};

exports.createResource = asyncHandler(async (req, res, next) => {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const userPasswordsDb = Password.doc(req.user.email).collection("passwords");
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

exports.getStore = asyncHandler(async (req, res, next) => {
    const userPasswordsDb = Password.doc(req.user.email).collection("passwords");
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

exports.updateResource = asyncHandler(async (req, res, next) => {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const id = req.params.id;
    const userPasswordsDb = Password.doc(req.user.email).collection("passwords");
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

exports.deleteResource = asyncHandler(async (req, res, next) => {
    const passwordsRef = Password.doc(req.user.email).collection("passwords");
    const accountRef = passwordsRef.doc(req.params.id);
    let account = await accountRef.get();

    if (!account.exists) res.status(400).send("Entry for this account does not exist.");

    await accountRef.delete();
    res.status(200).send();
});
