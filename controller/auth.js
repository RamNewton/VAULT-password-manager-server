const bcrypt = require("bcrypt");
const Joi = require("joi");
const passwordComplexity = require("joi-password-complexity");
const jwt = require("jsonwebtoken");
const blackList = require("../utils/blacklistToken");
const User = require("../model/user");
const asyncHandler = require("../middleware/asyncHandler");
const ErrorResponse = require("../utils/ErrorResponse");

exports.register = asyncHandler(async (req, res, next) => {
    const validate = (data) => {
        const complexityOptions = {
            min: 6,
            max: 256,
            numeric: 1,
            lowerCase: 0,
            upperCase: 0,
            symbol: 0,
            requirementCount: 3,
        };

        const schema = Joi.object({
            name: Joi.string()
                .pattern(/[a-zA-z ]+/, "name")
                .min(3)
                .max(50),
            email: Joi.string().email().required().min(3).max(255),
            password: passwordComplexity(complexityOptions),
        });

        return schema.validate(data);
    };

    const { error } = validate(req.body);
    // if (error) return res.status(400).send(error.details[0].message);
    if (error) return next(new ErrorResponse(error.details[0].message, 400));

    let _user = User.where("email", "==", req.body.email);
    user = await _user.get();
    // if (user.docs.length > 0) return res.status(400).send("This email id has already been registered");
    if (user.docs.length > 0) return next(new ErrorResponse("This email id has already been registered", 400));

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    await User.add({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
    });

    res.status(200).send();
});

exports.login = asyncHandler(async (req, res, next) => {
    const validate = (data) => {
        const schema = Joi.object({
            email: Joi.string().email().required().min(3).max(255),
            password: Joi.string(),
        });

        return schema.validate(data);
    };

    const { error } = validate(req.body);
    // if (error) return res.status(400).send(error.details[0].message);
    if (error) return next(new ErrorResponse(error.details[0].message, 400));

    let _user = User.where("email", "==", req.body.email);
    user = await _user.get();
    // if (user.docs.length == 0) return res.status(401).send("Invalid Email or Password");
    if (user.docs.length == 0) return next(new ErrorResponse("Invalid Email or Password", 401));
    user = user.docs[0];

    const validPassword = await bcrypt.compare(req.body.password, user.data().password);
    // if (!validPassword) return res.status(401).send("Invalid Email or Password");
    if (!validPassword) return next(new ErrorResponse("Invalid Email or Password", 401));

    const token = generateAuthToken(user);

    res.status(200)
        .cookie("token", token, { sameSite: "strict", path: "/", expires: new Date(new Date().getTime() + parseInt(process.env.TOKEN_EXPIRE_TIME) * 1000), httpOnly: true })
        .send();
});

exports.logout = asyncHandler(async (req, res, next) => {
    const token = req.cookies.token;
    if (token) blackList.addToken(token);
    res.status(200).send();
});

exports.loginStatus = asyncHandler(async (req, res, next) => {
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
    return jwt.sign({ email: user.data().email, _id: user.id }, process.env.jwtPrivateKey, { expiresIn: parseInt(process.env.TOKEN_EXPIRE_TIME) });
}
