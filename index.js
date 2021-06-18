const express = require("express");
var cookieParser = require("cookie-parser");
const cors = require("cors");
const morgan = require("morgan");
const authRouter = require("./routes/auth.js");
const dashboardRouter = require("./routes/passwords.js");
const errorHandler = require("./middleware/error");
const app = express();

app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());

if (process.env.NODE_ENV === "production") app.use(express.static(path.join(__dirname, "client/build")));
if (process.env.NODE_ENV !== "production") app.use(cors({ origin: "http://localhost:3000", credentials: true }));

app.use("/api/auth/", authRouter);
app.use("/api/main/", dashboardRouter);

if (process.env.NODE_ENV === "production") {
    app.get("*", (req, res) => {
        res.sendFile(path.join(__dirname + "/client/build/index.html"));
    });
}

app.use(errorHandler);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Listening on ${PORT}...`);
});
