const Joi = require('joi');

exports.signupValidation = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({
            tlds: { allow: ['com', 'net', 'in'] }
        }),

    password: Joi.string()
        .required()
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/)
});

exports.signinValidation = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({
            tlds: { allow: ['com', 'net', 'in'] }
        }),

    password: Joi.string()
        .required()
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/)
});

