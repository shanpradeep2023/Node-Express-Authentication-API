const nodeMailer = require('nodemailer')

const transport = nodeMailer.createTransport({
    service:'gmail',
    auth:{
        user:process.env.NODE_EMAIL_ADDRESS,
        pass:process.env.NODE_EMAIL_PASSWORD
    },
});

module.exports = transport;