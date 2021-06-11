const jwt = require("jsonwebtoken");
const blackList = require("../blacklistToken");

function auth(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).send({ message: "No Token" });

    try {
        const decoded = jwt.verify(token, process.env.jwtPrivateKey);
        const currentTime = Math.floor(+new Date() / 1000);
        if (decoded.exp < currentTime || blackList.tokenExists(token)) res.status(401).send({ message: "Expired Token" });
        req.user = decoded;
        next();
    } catch (ex) {
        res.status(401).send({ message: "Invalid Token" });
    }
}

module.exports = auth;
