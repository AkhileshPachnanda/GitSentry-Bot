const logger = require('../src/lib/logger');

describe('logger', () => {
  let logSpy;

  beforeEach(() => {
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    jest.resetModules();
  });

  test('logs error message with details', () => {
    logger.error('an error occurred', { code: 500 });
    expect(logSpy).toHaveBeenCalledWith('[ERROR]', 'an error occurred', { code: 500 });
  });

  test('logs warn message without details', () => {
    logger.warn('a warning message');
    expect(logSpy).toHaveBeenCalledWith('[WARN]', 'a warning message');
  });

  test('logs info message with details', () => {
    logger.info('some info', { user: 'test' });
    expect(logSpy).toHaveBeenCalledWith('[INFO]', 'some info', { user: 'test' });
  });

  test('does not log debug when LOG_LEVEL is default (info)', () => {
    logger.debug('some debug info');
    expect(logSpy).not.toHaveBeenCalled();
  });

  test('logs debug when LOG_LEVEL is set to debug', () => {
    // We isolate the module import to test env variable change
    process.env.LOG_LEVEL = 'debug';
    const debugLogger = require('../src/lib/logger');
    debugLogger.debug('some debug info', { data: 123 });
    expect(logSpy).toHaveBeenCalledWith('[DEBUG]', 'some debug info', { data: 123 });
    delete process.env.LOG_LEVEL;
  });

  test('honors error only LOG_LEVEL', () => {
    process.env.LOG_LEVEL = 'error';
    const errorLogger = require('../src/lib/logger');
    errorLogger.warn('warn should be ignored');
    errorLogger.error('error should be logged');
    expect(logSpy).not.toHaveBeenCalledWith('[WARN]', 'warn should be ignored');
    expect(logSpy).toHaveBeenCalledWith('[ERROR]', 'error should be logged');
    delete process.env.LOG_LEVEL;
  });
});
