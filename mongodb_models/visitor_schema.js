const mongoose = require('mongoose')

const visitorschema = mongoose.Schema(
    {
        full_name:{
            type: String,
            required: true
        },
        phone_number:{
            type: String,
            required: true
        },
        email:{
            type: String,
            required: true
        },
        license_number:{
            type: String,
            required: true
        },
        user_id:{
            type: mongoose.Schema.Types.ObjectId, 
            ref:'users'
        },
        visitor_pass_id:[{
            type: mongoose.Schema.Types.ObjectId, 
            ref:'visitor passes'
        }]
    },
    { versionKey: false }
)

const Visitor = mongoose.model('Visitor', visitorschema);
module.exports = Visitor;