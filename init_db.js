const admin = require("firebase-admin");

var serviceAccount = require("./service-account-key.json");
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: "password-manager-9a89b",
});

const db = admin.firestore();

module.exports = db;
