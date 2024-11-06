const { signupValidation, signinValidation, acceptedCodeValidation, changePasswordValidation, forgotPasswordCodeAndPasswordValidation } = require('../middlewares/validator');
const transport = require('../middlewares/sendMail')
const users = require('../models/users')
const { doHash, doHashValidation, hmacProcess } = require('../utils/hashing')


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

exports.sendValidationCode = async (req,res)=>{
    const {email} = req.body;
    try {
        const existingUser = await users.findOne({email})

        if(!existingUser){
            return res.status(404).json({success:false,message: 'User does not exists'})
        }
        if(existingUser.verified){
            return res.status(400).json({success:false, message:'User already verified..'})
        }

        const codeValue = Math.floor(Math.random() * 1000000).toString()
        const info = await transport.sendMail({
            from: process.env.NODE_EMAIL_ADDRESS,
            to: existingUser.email,
            subject:"Verification Code for Express Authorization Project",
            html: '<h1>' +codeValue + '</h1>'
        })

        if(info.accepted[0] === existingUser.email){
            const hashedCodeValue = hmacProcess(codeValue,process.env.HMAC_VERIFICATION_CODE_SECRET_KEY)
            existingUser.verificationCode = hashedCodeValue;
            existingUser.verificationCodeValidation = Date.now();
            await existingUser.save()

            return res.status(200).json({success:true,message:'verification code sent'});
        }

        return res.status(400).json({success:true,message:'verification code failed'});

    } catch (error) {
        console.log(error);
        res.status(500).json({success:false, message:'Internal server error...Could not send validation code'} )
    }
}

exports.verifyVerificationCode = async (req,res) =>{
    const {email,providedCode} = req.body;
    try {
        const {error, value} = acceptedCodeValidation.validate({email,providedCode})
        if(error){
            return res.status(401).json({success:false,message: error.details[0].message})
        }
        const codeValue = providedCode.toString()
        const existingUser = await users.findOne({email}).select('+verificationCode +verificationCodeValidation')

        if(!existingUser){
            return res.status(404).json({success:false,message: 'User does not exists'})
        }
        if(existingUser.verified){
            return res.status(400).json({success:false, message:'User already verified..'})
        }

        if(!existingUser.verificationCode || !existingUser.verificationCodeValidation){
            return res.status(400).json({success:false, message:'Something went wrong with code!!!'})
        }

        if(Date.now() - existingUser.verificationCodeValidation > 5*60*1000){
            return res.status(400).json({success:false, message:'Time limit for code verification exceeded!!'})
        }

        const hashedCodeValue = hmacProcess(codeValue,process.env.HMAC_VERIFICATION_CODE_SECRET_KEY)

        if(hashedCodeValue === existingUser.verificationCode){
            existingUser.verified = true;
            existingUser.verificationCode = undefined
            existingUser.verificationCodeValidation = undefined
            await existingUser.save()

            return res.status(200).json({success:true, message:'User verified successfully!!'})
        }else{
            return res.status(400).json({success:false, message:'Entered code is invalid!!'})

        }
    } catch (error) {
        console.log(error)
        return res.status(500).json({success:false, message:'Internal server error...Could not verify code'})
    }
}

exports.changePassword = async (req,res)=>{
    const {userId, verified} = req.user;
    const {oldPassword, newPassword} = req.body;

    try {
        const {error, value} = changePasswordValidation.validate({newPassword,oldPassword})
        if(error){
            return res.status(401).json({success:false,message: error.details[0].message})
        }
        
        const existingUser = await users.findOne({_id:userId}).select('+password')
        if(!existingUser){
            return res.status(404).json({success:false,message: 'User does not exists'})
        }

        if(!existingUser.verified){
            return res.status(401).json({success:false,message: 'User is not verified..'});
        }

        const result = await doHashValidation(oldPassword,existingUser.password)
        if(!result){
            return res.status(400).json({success:false, message:'Old password does not match with entered password!!'})
        }

        const hashedPassword = await doHash(newPassword,12);
        existingUser.password = hashedPassword;
        await existingUser.save();
        return res.status(200).json({success:true,message:'Password changed successfully!!'})

    } catch (error) {
        console.log(error);
        return res.status(500).json({success:false, message:'Internal server error!!'})

    }
}


exports.sendForgotPasswordCode = async (req,res)=>{
    const {email} = req.body;
    try {
        const existingUser = await users.findOne({email})

        if(!existingUser){
            return res.status(404).json({success:false,message: 'User does not exists'})
        }
        // if(existingUser.verified){
        //     return res.status(400).json({success:false, message:'User already verified..'})
        // }

        const codeValue = Math.floor(Math.random() * 1000000).toString()
        const info = await transport.sendMail({
            from: process.env.NODE_EMAIL_ADDRESS,
            to: existingUser.email,
            subject:" Forgot Password Verification Code for Express Authorization Project",
            html: '<h1>' +codeValue + '</h1>'
        })

        if(info.accepted[0] === existingUser.email){
            const hashedCodeValue = hmacProcess(codeValue,process.env.HMAC_VERIFICATION_CODE_SECRET_KEY)
            existingUser.forgotPasswordCode = hashedCodeValue;
            existingUser.forgotPasswordCodeValidation = Date.now();
            await existingUser.save()

            return res.status(200).json({success:true,message:'Forgot Password verification code sent'});
        }

        return res.status(400).json({success:true,message:'Forgot password verification code failed'});

    } catch (error) {
        console.log(error);
        res.status(500).json({success:false, message:'Internal server error...Could not send validation code'} )
    }
}

exports.verifyForgotPasswordCode = async (req,res) =>{
    const {email,providedCode, newPassword} = req.body;
    try {
        const {error, value} = forgotPasswordCodeAndPasswordValidation.validate({email,providedCode, newPassword})
        if(error){
            return res.status(401).json({success:false,message: error.details[0].message})
        }
        const codeValue = providedCode.toString()
        const existingUser = await users.findOne({email}).select('+forgotPasswordCode +forgotPasswordCodeValidation')

        if(!existingUser){
            return res.status(404).json({success:false,message: 'User does not exists'})
        }
        // if(existingUser.verified){
        //     return res.status(400).json({success:false, message:'User already verified..'})
        // }

        if(!existingUser.forgotPasswordCode || !existingUser.forgotPasswordCodeValidation){
            return res.status(400).json({success:false, message:'Something went wrong with code!!!'})
        }

        if(Date.now() - existingUser.forgotPasswordCodeValidation > 5*60*1000){
            return res.status(400).json({success:false, message:'Time limit for forgot password code verification exceeded!!'})
        }

        const hashedCodeValue = hmacProcess(codeValue,process.env.HMAC_VERIFICATION_CODE_SECRET_KEY)

        if(hashedCodeValue === existingUser.forgotPasswordCode){
            const hashedPassword = await doHash(newPassword,12);
            existingUser.password = hashedPassword;
            existingUser.forgotPasswordCode = undefined
            existingUser.forgotPasswordCodeValidation = undefined
            await existingUser.save()

            return res.status(200).json({success:true, message:'Password Changed after verification successfully!!'})
        }else{
            return res.status(400).json({success:false, message:'Entered code is invalid!!'})

        }
    } catch (error) {
        console.log(error)
        return res.status(500).json({success:false, message:'Internal server error...Could not verify code'})
    }
}

