const mongoose = require('mongoose')
const AutoIncrement = require('mongoose-sequence')(mongoose);



const residentschema = mongoose.Schema(
    {
        resident_number:{
            type: Number,
            unique: true
        },
        resident_name:{
            type: String,
            required: true
        },
        resident_phone_number:{
            type: String,
            required: true
        },
        resident_address:{
            type: String,
            required: true
        }
    },
    { versionKey: false }
)

// Apply the auto-increment logic using the mongoose-sequence plugin
residentschema.plugin(AutoIncrement, { inc_field: 'resident_number', start_seq: 0 });


const Resident = mongoose.model('Resident', residentschema);
module.exports = Resident;