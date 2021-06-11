const config = require("config");
const jwt = require("jsonwebtoken");

class BlackList {
    constructor() {
        this.blacklist = {};
    }

    addToken = (token) => {
        const decoded = jwt.verify(token, process.env.jwtPrivateKey);
        this.blacklist[token] = decoded.exp;
    };

    tokenExists = (token) => {
        return token in this.blacklist ? true : false;
    };

    purgeTokens = () => {
        const currentTime = Math.floor(+new Date() / 1000);
        for (let token in this.blacklist) {
            if (this.blacklist[token] < currentTime) delete this.blacklist[token];
        }
    };
}

blackList = new BlackList();

setInterval(blackList.purgeTokens, 3600 * 1000);

module.exports = blackList;
