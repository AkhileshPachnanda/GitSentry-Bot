const levels = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
};

const currentLevel = levels[process.env.LOG_LEVEL] ?? levels.info;

function log(level, message, details) {
  if (levels[level] > currentLevel) {
    return;
  }

  const prefix = `[${level.toUpperCase()}]`;
  if (details === undefined) {
    console.log(prefix, message);
    return;
  }

  console.log(prefix, message, details);
}

module.exports = {
  error(message, details) {
    log("error", message, details);
  },
  warn(message, details) {
    log("warn", message, details);
  },
  info(message, details) {
    log("info", message, details);
  },
  debug(message, details) {
    log("debug", message, details);
  },
};
