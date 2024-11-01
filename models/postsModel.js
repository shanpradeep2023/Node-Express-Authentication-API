const { required } = require('joi')
const mongoose = require('mongoose')

const postSchema = mongoose.Schema({
    title:{
        type: String,
        required:[true,'Title required!'],
        trim: true
    },

    description:{
        type: String,
        required:[true,'description required!'],
        trim: true
    },

    userId:{
        type:mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required:true
    }
},{
    timestamps:true
})

module.exports = mongoose.model('Post',postSchema)