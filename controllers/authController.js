const { signupValidation, signinValidation } = require('../middlewares/validator');
const transport = require('../middlewares/sendMail')
const users = require('../models/users')
const { doHash, doHashValidation } = require('../utils/hashing')


const jwt = require('jsonwebtoken')

exports.signup = async (req,res)=>{
    
    const {email,password} = req.body

    try {
        const {error, value} = signupValidation.validate({email,password})
        if(error){
            return res.status(401).json({success:false,message: error.details[0].message})
        }
        const existingUser = await users.findOne({email})

        if(existingUser){
            return res.status(401).json({success:false,message: 'User already exists'})
        }


        const hashedPassword = await doHash(password, 12)

        const newUser = new users({
            email,
            password:hashedPassword
        })

        const result = await newUser.save()
        result.password = undefined
        res.status(201).json({
            success: true,
            message: "Account created successfully",result
        })

    } catch (error) {
        console.log(error)
        return res.status(500).json({success:false,message:"Internal server error"})
    }
}

exports.signin = async (req,res)=>{
    const {email,password} = req.body
    try {
        const {error, value} = signinValidation.validate({email,password})
        if(error){
            return res.status(401).json({success:false,message: error.details[0].message})
        }

        const existingUser = await users.findOne({email}).select('password')

        if(!existingUser){
            return res.status(401).json({success:false,message: 'User does not exists'})
        }

        const result = await doHashValidation(password,existingUser.password)
        if(!result){
            return res.status(401).json({success:false,message: 'Invalid credentials'})
        }

        const token = jwt.sign({
            userId:existingUser._id,
            email:existingUser.email,
            verified:existingUser.verified,
        },process.env.TOKEN_SECRET,{expiresIn: '8h'});

        res.cookie('Authorization','Bearer' +token, {expires: new Date(Date.now() + 8*3600000),
            httpOnly:process.env.NODE_ENV === 'production', 
            secure:process.env.NODE_ENV === 'production'
        }).json({
            success:true,
            token,
            message:"Login Successful.."
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({success:false,message:"Internal server error"})
    }
}


exports.signout = async (req,res)=>{
    res.clearCookie('Authorization').status(200).json({success:true, message:'Logged Out Successfully!'})
};

// exports.sendValidationCode = async (req,res)=>{
//     const {email} = req.body;
//     try {
//         const existingUser = await users.findOne({email})

//         if(!existingUser){
//             return res.status(404).json({success:false,message: 'User does not exists'})
//         }
//         if(existingUser.verified){
//             return res.status(400).json({success:false, message:'User already verified..'})
//         }

//         const codeValue = Math.floor(Math.random() * 1000000).toString()
//         const info = await transport.sendMail({
//             from: process.env.NODE_EMAIL_ADDRESS,
//             to: existingUser.email,
//             subject:"Verification Code for Express Authorization Project",
//             html: '<h1>' +codeValue + '</h1>'
//         })

//         if(info.accepted[0] === exixtingUser.email){

//         }

//     } catch (error) {
//         console.log(error);
//         res.status(500).json({success:false, message:'Internal server error...Could not send validation code'} )
//     }
// }