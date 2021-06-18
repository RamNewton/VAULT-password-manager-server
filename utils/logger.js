const { createLogger, format, transports } = require("winston");

const logger = createLogger({
    transports: new transports.File({
        filename: "logs/server.log",
        format: format.combine(
            format.timestamp({ format: "MMM-DD-YYYY HH:mm:ss" }),
            format.align(),
            format.printf((info) => `${info.level}: ${[info.timestamp]}: ${info.message}`)
        ),
    }),
});

if (process.env.NODE_ENV !== "production") {
    logger.add(
        new transports.Console({
            format: format.simple(),
        })
    );
}

module.exports = logger;
