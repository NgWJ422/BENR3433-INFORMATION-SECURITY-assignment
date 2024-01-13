const mongoose = require('mongoose')

const visitor_pass_schema = mongoose.Schema(
    {
        visitor_id:{
            type: mongoose.Schema.Types.ObjectId,
            ref:'visitors'
        },
        resident_number: {
            type: mongoose.Schema.Types.Number,
            ref: 'residents'
          },
        purpose_of_visit:{
            type: String,
            required: true
        },
        approval:{
            type: Boolean,
            required: true
        },
        checkin_time:{
            type: String
        },
        checkout_time:{
            type: String
        },
        remarks:{
            type: String,
            required: true
        },
    },
    { versionKey: false }
)
const Pass = mongoose.model('Visitor Pass', visitor_pass_schema);
module.exports = Pass;