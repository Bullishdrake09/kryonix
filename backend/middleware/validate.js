/**
 * Kryonix — Input Validation Middleware (using joi)
 */
'use strict';

const Joi = require('joi');

function validate(schema, property = 'body') {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[property], { abortEarly: false, stripUnknown: true });
    if (error) {
      return res.status(422).json({
        error: 'Validation failed',
        details: error.details.map(d => d.message),
      });
    }
    req[property] = value;
    next();
  };
}

// Common schemas
const schemas = {
  register: Joi.object({
    username:     Joi.string().alphanum().min(3).max(32).required(),
    displayName:  Joi.string().min(1).max(64).required(),
    password:     Joi.string().min(12).max(128).required(),
    keyBundle: Joi.object({
      identityKey:           Joi.string().hex().length(130).required(),
      signedPrekey:          Joi.string().hex().length(130).required(),
      signedPrekeyId:        Joi.number().integer().required(),
      signedPrekeySignature: Joi.string().hex().min(128).required(),
      oneTimePrekeys:        Joi.array().items(Joi.object({
        id:        Joi.number().integer().required(),
        publicKey: Joi.string().hex().length(130).required(),
      })).min(10).max(100).required(),
    }).required(),
  }),
  login: Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required(),
    deviceId: Joi.string().uuid().optional(),
  }),
  sendMessage: Joi.object({
    conversationId: Joi.string().required(),
    ciphertext:     Joi.string().hex().required(),
    iv:             Joi.string().hex().length(24).required(),
    ephemeralKey:   Joi.string().hex().optional(),
    msgNumber:      Joi.number().integer().min(0).default(0),
    type:           Joi.string().valid('text','file','system').default('text'),
    fileRef:        Joi.object().optional(),
  }),
  aiGenerate: Joi.object({
    model:          Joi.string().max(64).required(),
    prompt:         Joi.string().max(4096).required(),
    systemPrompt:   Joi.string().max(1024).optional(),
    stream:         Joi.boolean().default(true),
    contextMessages:Joi.array().items(Joi.object({
      role:    Joi.string().valid('user','assistant').required(),
      content: Joi.string().max(2048).required(),
    })).max(20).default([]),
    options: Joi.object({
      temperature: Joi.number().min(0).max(2).default(0.7),
      top_p:       Joi.number().min(0).max(1).default(0.9),
    }).default({}),
  }),
};

module.exports = { validate, schemas };
