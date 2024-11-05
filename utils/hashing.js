const hash = require('bcryptjs')
const { createHmac } = require('crypto')

exports.doHash = (password, saltValue)=>{
    const result = hash.hash(password,saltValue)
    return result
}

exports.doHashValidation = (password, hashedPassword)=>{
    const result = hash.compare(password,hashedPassword)
    return result
}

exports.hmacProcess = (value,key)=>{
    const result = createHmac('sha256',key).update(value).digest('hex')
    return result
}