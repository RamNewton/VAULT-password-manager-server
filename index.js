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
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(cookieParser());
app.use("/api/auth/", authRouter);
app.use("/api/main/", dashboardRouter);
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Listening on ${PORT}...`);
});
