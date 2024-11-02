const hash = require('bcryptjs')

exports.doHash = (password, saltValue)=>{
    const result = hash.hash(password,saltValue)
    return result
}

exports.doHashValidation = (password, hashedPassword)=>{
    const result = hash.compare(password,hashedPassword)
    return result
}

