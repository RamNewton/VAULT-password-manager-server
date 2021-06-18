const ErrorResponse = require("../utils/ErrorResponse");
const logger = require("../utils/logger");

const errorHandler = (err, req, res, next) => {
    let error = { ...err };
    // message is not present as a property explicity on an Error object (ErrorResponse is inherited from it)
    // So we have to explicity access err.message
    error.message = err.message;

    res.status(error.statusCode || 500).send({ Error: error.message });
    logger.error(`${error.statusCode} - ${res.statusMessage} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
};

module.exports = errorHandler;
