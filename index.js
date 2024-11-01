const express = require('express')
const helmet = require('helmet')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const mongoose = require('mongoose')

const authRouter = require('./routers/authRouter')

const app = express()

app.use(cors())
app.use(helmet())
app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({extended:true}))

mongoose.connect(process.env.MONGODB_URL).then(()=>{
    console.log("DB connected..")
}).catch((err) =>{
    console.log(err)
});

app.use('/auth',authRouter)

app.get('/', (req,res) => {
    res.json({message: "hello from server root request...."})
});

app.listen(process.env.PORT,()=>{
    console.log(`server is running on port ${process.env.PORT}`);
});