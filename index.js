const express = require("express");
var cookieParser = require("cookie-parser");
const cors = require("cors");
const auth_router = require("./auth.js");
const main_router = require("./passwords.js");

const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(cookieParser());
app.use("/api/auth/", auth_router);
app.use("/api/main/", main_router);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Listening on ${PORT}...`);
});
