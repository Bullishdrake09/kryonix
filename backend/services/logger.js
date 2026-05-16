/**
 * Kryonix — Logger (winston)
 */
'use strict';

const { createLogger, format, transports } = require('winston');
const path = require('path');

const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.errors({ stack: true }),
    format.json()
  ),
  defaultMeta: { service: 'kryonix' },
  transports: [
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.printf(({ timestamp, level, message, ...meta }) => {
          const extra = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
          return `${timestamp} [${level}] ${message}${extra}`;
        })
      ),
    }),
    new transports.File({
      filename: path.join(__dirname, '../../logs/error.log'),
      level:    'error',
      maxsize:  10 * 1024 * 1024,
      maxFiles: 5,
    }),
    new transports.File({
      filename: path.join(__dirname, '../../logs/combined.log'),
      maxsize:  20 * 1024 * 1024,
      maxFiles: 10,
    }),
  ],
});

module.exports = { logger };
