const mongoose = require('mongoose')

const userschema = mongoose.Schema(
    {
        username:{
            type: String,
            required:true
        },
        password:{
            type: String,
            required: true
        },
        name:{
            type: String,
            required: true
        },
        role:{
            type: String,
            enum: ['user', 'security','admin'],
            required: true
        },
        visitor_id:[{
            type: mongoose.Schema.Types.ObjectId,
            ref:'visitors'
        }],
        approval:{
            type: Boolean
        },
        login_status:{
            type: Boolean
        }
    },
    { versionKey: false }
)
const User = mongoose.model('User', userschema);
module.exports = User;