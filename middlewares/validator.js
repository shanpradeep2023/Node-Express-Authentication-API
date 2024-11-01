const Joi = require('joi')

exports.signupSchema = Joi.object({
    email: Joi.string()
            .min(6)
            .max(60)
            .required()
            .email({
        tlds: { allow: ['com','net','in']}
    }),

    password: Joi.string()
            .required()
            .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?.*d).{8,}$'))
})