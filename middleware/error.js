const ErrorResponse = require("../utils/ErrorResponse");

const errorHandler = (err, req, res, next) => {
    let error = { ...err };
    // message is not present as a property explicity on an Error object (ErrorResponse is inherited from it)
    // So we have to explicity access err.message
    error.message = err.message;

    // Mongoose validation error
    if (err.name === "ValidationError") {
        const message = Object.values(err.errors).map((val) => val.message);
        error = new ErrorResponse(message, 400);
    }

    res.status(error.statusCode || 500).send({ Error: error.message });
};

module.exports = errorHandler;
