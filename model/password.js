const db = require("../utils/initDB");
const Password = db.collection("passwords");
module.exports = Password;
