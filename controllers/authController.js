const signupSchema = require('../middlewares/validator')
const users = require('../models/users')

exports.signup = async (req,res)=>{
    //res.json({ message: "signup Success"})
    const {email,password} = req.body

    try {
        const {error, value} = signupSchema.validate({email,password})
        if(error){
            return res.status(401).json({success:false,message: error.details[0].message})
        }
        const existingUser = await users.findOne({email})

        if(existingUser){
            return res.status(401).json({success:false,message: 'User already exists'})
        }


    } catch (error) {
        console.log(error)
    }
}