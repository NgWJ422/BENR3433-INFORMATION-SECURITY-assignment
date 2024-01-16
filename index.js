require('dotenv').config()
const express = require('express')
const bcrypt = require('bcrypt');
const mongoose = require('mongoose')
const User = require('./mongodb_models/user_schema')
const Visitor = require('./mongodb_models/visitor_schema')
const Pass = require('./mongodb_models/visitor_pass_schema')
const Resident = require('./mongodb_models/resident_schema')
const jwt = require('jsonwebtoken')
const app = express()
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const rateLimit = require('express-rate-limit');
const validator = require('validator');



const port = process.env.PORT || 3000;



app.use(express.json())

// Enable if you're behind a proxy (e.g., Heroku, Nginx)
app.set('trust proxy', 1);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  handler: (req, res) => {
    res.status(429).json({
      status: 'error',
      message: 'Too many requests. Please try again later.',
    });
  },
});

// Apply the rate limiter to all routes
app.use(limiter);

const validatePassword = (password) => {
  // Minimum 8 characters
  const passwordRegex = /^.{8,}$/;

  return passwordRegex.test(password);
};



const options = {
    definition: {
      openapi: '3.0.0',
      info: {
        title: 'WJ BENR3433 INFORMATION SECURITY assignment G15',
        description:'Ng Wei Jie  B022110102 Chan Zen Yang  B022110113',
        version: '1.0.0',
      },
      tags:[
        { name: 'test', description: 'testing endpoints' },
        { name: 'Resident', description: 'Create residents(for admin only)' },
        { name: 'User', description: 'Endpoints related to users' },
        { name: 'Visitor', description: 'Endpoints related to visitor' },
        { name: 'Security', description: 'Endpoints related to security' },
        { name: 'Read', description: 'Endpoints to read own file' },
        { name: 'For Admin Only', description: 'Endpoints for admin to manage user' },
      ],
      components: {
        securitySchemes: {
            Authorization: {
                type: "http",
                scheme: "bearer",
                bearerFormat: "JWT",
                value: "Bearer <JWT token here>",
                description:"this is for authentication only, to log out, please use the logout api. Logout here won't log you out of the account"
            }
          }
        },
      servers:[
        {
            url: 'https://benr3433-information-security-assignment.azurewebsites.net/'
            //remember to change current ip address in MongoDB Network Access List
            //url: 'http://localhost:3000'
        }
      ]
    },
    apis: ['./swagger.js'],
  };
  
  const openapiSpecification = swaggerJsdoc(options);
  app.use('/swagger', swaggerUi.serve, swaggerUi.setup(openapiSpecification));


//connect using password

// mongoose.connect(process.env.mongo_url)
//  .then(()=>{
//      console.log('connected to mongodb')
//      app.listen(port,() => {
//          console.log(`Node Api is running on port ${port}`)
//      })
//  }).catch((error)=>{
//      console.log(error)
//  })

//connect using X509 cert
const url = process.env.mongo_x509_url;
mongoose.connect(url, {
  tls: true,
  // location of a local .pem file that contains both the client's certificate and key
  tlsCertificateKeyFile: 'X509-cert-4070599474815490296.pem',
  authMechanism: 'MONGODB-X509',
  authSource: '$external',
}).then(()=>{
       console.log('connected to mongodb through X509 ceritificate')
       app.listen(port,() => {
           console.log(`Node Api is running on port ${port}`)
       })
   }).catch((error)=>{
       console.log(error)
   })


app.get('/', (req, res) => {
    res.send('Hello World! NgWJ')
 })





//for penetration testing(no need for approval)
 app.post('/test/register', async (req, res) => {
  try {
    const { username, password, name, role } = req.body;
    const existingUser = await User.findOne({ 'username': username });

    if (existingUser) {
      return res.status(409).send('Username has been taken');
    }

    if (!validatePassword(req.body.password)) {
      return res.status(400).send('Invalid password. Please follow the password policy.');
    }

    const hash = await bcrypt.hash(password, 10);
    const request = {
      username: username,
      password: hash,
      name: name,
      role: role,
      approval: true,
      login_status: false
    };

    const user = await User.create(request);
    const responseMessage = 'User registered successfully';
    
    return res.status(200).json({
      username: user.username,
      name: user.name,
      message: responseMessage
    });
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: error.message });
  }
});

//create a new user(need approval)
app.post('/register', async(req, res) => {
    try {
        const { username, password, name} = req.body;
        const a = await User.findOne({'username':req.body.username})
        console.log('Received Password:', password); 
        if (!validatePassword(password)) {
          return res.status(400).send('Invalid password. Please follow the password policy.');
        }


        const hash = await bcrypt.hash(password, 10)
        if(a == null){
          const request ={
            username: username,
            password: hash,
            name: name,
            role: "user",
            approval: false,
            login_status: false
          }  
          const user = await User.create(request)
          const responsemessage= 'User registration pending';
          res.status(200).json({username:user.username,name:user.name, message: responsemessage})}
        else{
            res.status(409).send('Username has been taken');
        }        
    } catch (error) {
        console.log(error.message);
        res.status(500).json({message: error.message})
    }
})

//create a new resident(for admin)
app.post('/resident/register',authenticateToken, async(req, res) => {
  try {
      const loggedInUser = await User.findOne({ _id: req.user.user_id });

      // Check user's authentication and admin role
      if (!loggedInUser || loggedInUser.login_status !== true || loggedInUser.role !== 'admin') {
        return res.status(403).send('Unauthorized: Admin access only');
      }
      const { resident_name, resident_phone_number, resident_address} = req.body;
      const newResident = await Resident.create(
        {
          resident_name: resident_name,
          resident_phone_number: resident_phone_number,
          resident_address: resident_address
        }
      )
      const responsePayload = {
        resident_number: newResident.resident_number,
        resident_name: newResident.resident_name,
        resident_phone_number: newResident.resident_phone_number,
        resident_address: newResident.resident_address,
      };
  
      res.status(200).json(responsePayload);
  } catch (error) {
      console.log(error.message);
      res.status(500).json({message: error.message})
  }
})

//login for user,security and admin
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(404).send('Username not found');
    }

    if (user.login_status) {
      return res.status(409).send('User is already logged in');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send('Unauthorized: Wrong password');
    }

    if (user.approval != true) {
      return res.json({ username: user.username, message: 'Registration pending, please logout and wait patiently' });
    }

    // Update login_status to true
    await User.updateOne({ username }, { $set: { login_status: true } });

    // Generate JWT token
    const accessToken = jwt.sign({ username: user.username, user_id: user._id }, process.env.JWT_SECRET);
    if(user.role == 'admin' ){
      const allUsers = await User.find();
      const allVisitors = await Visitor.find();
      const allPasses = await Pass.find();
      const allresident = await Resident.find();
  
       return res.status(200).json({
        username: user.username,
        role:user.role,
        message: 'Login successful',
        token: accessToken,
        Users: allUsers,
        Visitors: allVisitors,
        Visitor_Passes: allPasses,
        Resident: allresident
      });
    }
    res.json({ username: user.username, role:user.role , message: 'Login successful', token: accessToken });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: error.message });
  }
});

//middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) return res.sendStatus(401)

  jwt.verify(token, process.env.JWT_SECRET, (err, login_user) => {
    console.log(err)
    if (err) return res.sendStatus(403)
    req.user = login_user
    next()
  })
}

//test jwt
app.get('/showjwt',authenticateToken,(req,res)=>{
  res.send(req.user)
})

//user logout(cannot interact with api after log out)
app.patch('/logout', async (req, res) => {
  const { username } = req.body;
  try {
    const a = await User.findOne({ username: req.body.username });
    if (a == null) {
      res.status(404).send('Username not found');
    } else {
      if (a.login_status !== true) {
        res.status(400).send("User has already logged out");
      } else {
        await User.updateOne({ username: req.body.username }, { $set: { login_status: false } });
        res.status(200).send("Successfully logged out");
      }
    }
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ message: error.message });
  }
});

/**
 * Endpoint to register a visitor for a user
 */
app.post('/visitor/register', authenticateToken, async (req, res) => {
  try {
    // Check if the user is logged in
    const loggedInUser = await User.findOne({ _id: req.user.user_id });
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    // Create a visitor record
    const newVisitorData = {
      full_name: req.body.full_name,
      phone_number: req.body.phone_number,
      email: req.body.email,
      license_number: req.body.license_number,
      user_id: req.user.user_id // Link the visitor to the logged-in user
    };

    // Create the visitor
    const visitor = await Visitor.create(newVisitorData);

    // Update the user's visitor_id field with the newly created visitor's ID
    await User.updateOne({ _id: req.user.user_id }, { $push: { 'visitor_id': visitor._id } });

    // Return the newly created visitor details
    return res.status(200).json(visitor);
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: 'Internal server error occurred' });
  }
});


/**
 * Endpoint to create a visitor pass
 */
app.post('/visitor/visitor_pass/:id', authenticateToken, async (req, res) => {
  try {
    // Check if the user is logged in
    const loggedInUser = await User.findOne({ _id: req.user.user_id });
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    // Check if the specified visitor exists
    const vvisitor = await Visitor.findOne({ _id: req.params.id });
    if (!vvisitor) {
      return res.status(404).send('Visitor not found');
    }

    // Check if the visitor belongs to the logged-in user
    if (vvisitor.user_id != req.user.user_id) {
      return res.status(403).send('The visitor does not belong to this user');
    }

    const vresident = await Resident.findOne({resident_number: req.body.resident_number})
    if(!vresident){
      return res.status(404).send('resident does not exist')
    }

    // Create a new visitor pass
    const newVisitorPass = {
      visitor_id: vvisitor._id,
      resident_number: req.body.resident_number,
      purpose_of_visit: req.body.purpose_of_visit,
      approval: false,
      remarks: req.body.remarks
    };

    // Save the visitor pass details
    const createdVisitorPass = await Pass.create(newVisitorPass);

    // Update the visitor with the newly created visitor pass ID
    await Visitor.updateOne(
      { _id: vvisitor._id },
      { $push: { 'visitor_pass_id': createdVisitorPass._id } }
    );

    // Return the newly created visitor pass details
    return res.status(201).json(createdVisitorPass);
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: 'Internal server error occurred' });
  }
});



//read own user profile
app.get('/read/user', authenticateToken, async (req, res) => {
  try {
    // Find the logged-in user document
    const loggedInUser = await User.findOne({ _id: req.user.user_id, login_status: true });

    // Check if the logged-in user exists and is logged in
    if (!loggedInUser) {
      return res.status(401).send('Please login');
    }

    // Respond with the user document
    res.status(200).json(loggedInUser);
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ message: 'Internal server error occurred' });
  }
});

//read own visitor profile
app.get('/read/visitor', authenticateToken, async (req, res) => {
  try {
    // Find the logged-in user document
    const loggedInUser = await User.findOne({ _id: req.user.user_id, login_status: true });

    // Check if the logged-in user exists and is logged in
    if (!loggedInUser) {
      return res.status(401).send('Please login');
    }

    const associatedVisitors = await Visitor.find({ user_id: loggedInUser._id });
    res.status(200).json(associatedVisitors);
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ message: 'Internal server error occurred' });
  }
});


// Read all visitor passes for all visitors of the logged-in user
app.get('/read/visitor_pass', authenticateToken, async (req, res) => {
  try {
    // Find the logged-in user document
    const loggedInUser = await User.findOne({ _id: req.user.user_id, login_status: true });

    // Check if the logged-in user exists and is logged in
    if (!loggedInUser) {
      return res.status(401).send('Please login');
    }

    // Create an object to store passes for each visitor
    const passesByVisitor = {};

    // Retrieve visitor passes for all visitors of the logged-in user
    for (const visitorId of loggedInUser.visitor_id) {
      const passesForVisitor = await Pass.find({ visitor_id: visitorId });
      passesByVisitor[visitorId] = passesForVisitor;
    }

    res.status(200).json(passesByVisitor);
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ message: 'Internal server error occurred' });
  }
});


// Read one visitor pass based on its ID
app.get('/read/visitor_pass/:id', authenticateToken, async (req, res) => {
  try {
    const loggedInUser = await User.findOne({ _id: req.user.user_id });
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    const vpass = await Pass.findOne({ _id: req.params.id });
    if (!vpass) {
      return res.status(404).json({ message: 'Visitor pass not found' });
    }

    const pvisitor = await Visitor.findOne({ _id: vpass.visitor_id });
    if (pvisitor.user_id != req.user.user_id) {
      return res.status(403).json({ message: 'This visitor pass does not belong to your visitor' });
    }

    return res.json(vpass);
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: 'Internal server error occurred' });
  }
});



//retrieve phone number of the visitor from visitor pass
app.get('/security/pass/hp/:id', authenticateToken, async (req, res) => {
  try {
    // Check if the user is logged in
    const loggedInUser = await User.findOne({ _id: req.user.user_id });
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    if (loggedInUser.role !== 'admin' && loggedInUser.role !== 'security') {
      return res.status(403).send('Unauthorized: Admin and security access only');
    }

    // Try finding the specific visitor pass
    let a;
    try {
      a = await Pass.findOne({ _id: req.params.id });
    } catch (error) {
      console.log(error.message);
      return res.status(500).json({ message: error.message });
    }

    if (!a) {
      return res.status(404).json({ message: 'Visitor pass not found' });
    }

    const v = await Visitor.findOne({_id:a.visitor_id});
    return res.status(200).json({ phone_number: v.phone_number });
    
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: 'Internal server error occurred' });
  }
});

//security pending user approve
app.patch('/security/user/approval', authenticateToken, async (req, res) => {
  try {
    const p_user_id = req.body.id;
    const loggedInUser = await User.findOne({ _id: req.user.user_id });

    // Check user's authentication and admin/security role
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    // Check user's authentication and admin/security role
    if (loggedInUser.role !== 'admin' && loggedInUser.role !== 'security') {
      return res.status(403).send('Unauthorized: Admin and security access only');
    }

    const pendinguser = await User.findOne({ _id: p_user_id });
    if (!pendinguser) {
      return res.status(404).send('Pending user not found');
    }

    if (pendinguser.approval === true) {
      return res.status(400).send('User has already been approved');
    }

    const approved_user = await User.findOneAndUpdate({ _id: p_user_id }, { approval: true }, { new: true });

    res.status(200).json({
      username: approved_user.username,
      approval: approved_user.approval,
      message: 'User has been approved'
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//security read pending user
app.get('/security/read/user/pending', authenticateToken, async (req, res) => {
  try {
    // Check if the user is logged in
    const loggedInUser = await User.findOne({ _id: req.user.user_id });

    // If the user is not logged in or login status is not true, return 401 (Unauthorized)
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    // Check user's authentication and admin/security role
    if (loggedInUser.role !== 'admin' && loggedInUser.role !== 'security') {
      return res.status(403).send('Unauthorized: Admin and security access only');
    }

    // Find users with approval status as false
    const pendingUsers = await User.find({ approval: false });

    // Send the list of pending users as a JSON response
    res.status(200).json(pendingUsers);
    
  } catch (error) {
    // Log the error to console
    console.log(error.message);
    
    // Return a 500 (Internal Server Error) along with an error message
    return res.status(500).json({ message: 'Internal server error occurred' });
  }
});

//security check visitor pass
app.post('/security/read/pass', authenticateToken, async (req, res) => {
  try {
    // Check if the user is logged in
    const loggedInUser = await User.findOne({ _id: req.user.user_id });
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    // Check user's authentication and admin/security role
    if (loggedInUser.role !== 'admin' && loggedInUser.role !== 'security') {
      return res.status(403).send('Unauthorized: Admin and security access only');
    }

    const passlist = await Pass.find(req.body)
    return res.status(200).json(passlist);
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: 'Internal server error occurred' });
  }
});


//security read details of resident
app.post('/security/read/resident', authenticateToken, async (req, res) => {
  try {
    // Check if the user is logged in
    const loggedInUser = await User.findOne({ _id: req.user.user_id });

    // If the user is not logged in or login status is not true, return 401 (Unauthorized)
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    // Check user's authentication and admin/security role
    if (loggedInUser.role !== 'admin' && loggedInUser.role !== 'security') {
      return res.status(403).send('Unauthorized: Admin and security access only');
    }

    if (isNaN(req.body.resident_number)) {
      return res.status(400).send('Invalid resident number');
    }
    const residentDetails = await Resident.findOne({ resident_number: req.body.resident_number });
    if (!residentDetails) {
      return res.status(404).send('Resident not found');
    }
    res.status(200).json(residentDetails);
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ message: 'Internal server error occurred' });
  }
});

//security approve visitor pass
app.patch('/security/pass/approval/:id', authenticateToken, async (req, res) => {
  try {
    const loggedInUser = await User.findOne({ _id: req.user.user_id });

    // Check user's authentication and admin/security role
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    // Check user's authentication and admin/security role
    if (loggedInUser.role !== 'admin' && loggedInUser.role !== 'security') {
      return res.status(403).send('Unauthorized: Admin and security access only');
    }

    const pendingpass = await Pass.findOne({ _id: req.params.id });
    if (!pendingpass) {
      return res.status(404).send('Pending visitor pass not found');
    }

    if (pendingpass.approval === true) {
      return res.status(400).send('Pass has already been approved');
    }

    const approved_pass = await Pass.findOneAndUpdate({ _id: req.params.id }, { approval: true }, { new: true });

    res.status(200).json({
      Pass: approved_pass,
      message: 'Pass has been approved'
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//security checkin a visitor pass
app.patch('/security/pass/checkin/:id', authenticateToken, async (req, res) => {
  try {
    const loggedInUser = await User.findOne({ _id: req.user.user_id });

    // Check user's authentication and admin/security role
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    // Check user's authentication and admin/security role
    if (loggedInUser.role !== 'admin' && loggedInUser.role !== 'security') {
      return res.status(403).send('Unauthorized: Admin and security access only');
    }

    const vpass = await Pass.findOne({ _id: req.params.id });
    if (!vpass) {
      return res.status(404).send('visitor pass not found');
    }

    if (vpass.approval === false) {
      return res.send('Pass has not been approved');
    }

    if(vpass.checkin_time != null){
      return res.send('Pass has been check in');
    }

    if(vpass.checkout_time != null){
      return res.send('Pass has been check out');
    }
    const date = new Date().toISOString();
    const checkin_pass = await Pass.findOneAndUpdate({ _id: req.params.id }, { $set: { checkin_time: date } }, { new: true });

    res.status(200).json(checkin_pass);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//security checkout a visitor pass
app.patch('/security/pass/checkout/:id', authenticateToken, async (req, res) => {
  try {
    const loggedInUser = await User.findOne({ _id: req.user.user_id });

    // Check user's authentication and admin/security role
    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    // Check user's authentication and admin/security role
    if (loggedInUser.role !== 'admin' && loggedInUser.role !== 'security') {
      return res.status(403).send('Unauthorized: Admin and security access only');
    }

    const vpass = await Pass.findOne({ _id: req.params.id });
    if (!vpass) {
      return res.status(404).send('visitor pass not found');
    }

    if (vpass.approval === false) {
      return res.send('Pass has not been approved');
    }

    if(vpass.checkin_time == null){
      return res.send('Pass has not been check in');
    }

    if(vpass.checkout_time != null){
      return res.send('Pass has been check out');
    }
    const date = new Date().toISOString();
    const checkin_pass = await Pass.findOneAndUpdate({ _id: req.params.id }, { $set: { checkout_time: date } }, { new: true });

    res.status(200).json(checkin_pass);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//Admin Dump API
app.get('/admin/dump', authenticateToken, async (req, res) => {
  try {
    const loggedInUser = await User.findOne({ _id: req.user.user_id });

    if (!loggedInUser || loggedInUser.login_status !== true) {
      return res.status(401).send('Please login');
    }

    if (loggedInUser.role !== 'admin') {
      return res.status(403).send('You are not an admin');
    }

    const allUsers = await User.find();
    const allVisitors = await Visitor.find();
    const allPasses = await Pass.find();
    const allresident = await Resident.find();

    res.status(200).json({
      Users: allUsers,
      Visitors: allVisitors,
      Visitor_Passes: allPasses,
      Resident: allresident
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});


//admin read any document(S)
app.post('/admin/read/:collections', authenticateToken, async (req, res) => {
  try {
    const loggedInUser = await User.findOne({ _id: req.user.user_id });

    // Check user's authentication and admin role
    if (!loggedInUser || loggedInUser.login_status !== true || loggedInUser.role !== 'admin') {
      return res.status(403).send('Unauthorized: Admin access only');
    }

    const collections = req.params.collections;
    const filters = req.body;

    // Validate the requested collections
    const validcollections = ['User', 'Visitor', 'Visitor_Pass','Resident'];
    if (!collections || !validcollections.includes(collections)) {
      return res.status(400).send('Invalid or missing collections parameter');
    }

    // Based on the collections parameter, perform the query
    let queryResult;
    if (collections === 'User') {
      queryResult = await User.find(filters);
    } else if (collections === 'Visitor') {
      queryResult = await Visitor.find(filters);
    } else if (collections === 'Visitor_Pass') {
      queryResult = await Pass.find(filters);
    } else if (collections === 'Resident') {
      queryResult = await Resident.find(filters);
    }

    res.status(200).json(queryResult);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//admin update any document(S)
app.post('/admin/update/:id', authenticateToken, async (req, res) => {
  try {
    const loggedInUser = await User.findOne({ _id: req.user.user_id });

    // Check user's authentication and admin role
    if (!loggedInUser || loggedInUser.login_status !== true || loggedInUser.role !== 'admin') {
      return res.status(403).send('Unauthorized: Admin access only');
    }

    const { collections } = req.query;
    const update = req.body;
    const doc_id = req.params.id

    // Validate the requested collections
    const validcollections = ['User', 'Visitor', 'Visitor_Pass','Resident'];
    if (!collections || !validcollections.includes(collections)) {
      return res.status(400).send('Invalid or missing collections parameter');
    }

    // Ensure the update object is not empty
    if (Object.keys(update).length === 0) {
      return res.status(400).send('Update object cannot be empty');
    }

    // Based on the collections parameter, perform the update
    let updateresult;

    if (collections === 'User') {
      updateresult = await User.findOneAndUpdate({_id: doc_id},update,{new: true});
    } else if (collections === 'Visitor') {
      updateresult = await Visitor.findOneAndUpdate({_id: doc_id},update,{new: true});
    } else if (collections === 'Visitor_Pass') {
      updateresult = await Pass.findOneAndUpdate({_id: doc_id},update,{new: true});
    } else if (collections === 'Resident') {
      updateresult = await Resident.findOneAndUpdate({_id: doc_id},update,{new: true});
    }

    res.status(200).json(updateresult);
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});


//admin delete a user and all his visitor and visitor_pass documents
app.delete('/admin/delete/all/user/:id', authenticateToken, async (req, res) => {
  try {
    // Check if the logged-in user is an admin
    const loggedInUser = await User.findOne({ _id: req.user.user_id });
    if (!loggedInUser || loggedInUser.login_status !== true || loggedInUser.role !== 'admin') {
      return res.status(403).send('Unauthorized: Admin access only');
    }

    // Find and delete the user based on the provided ID
    const deletedUser = await User.findByIdAndDelete(req.params.id);

    // If the user is not found, return a 404 response
    if (!deletedUser) {
      return res.status(404).send('User not found');
    }

    // Get the visitor IDs from the deleted user
    const visitorIds = deletedUser.visitor_id;

    // Delete related data in other collections based on the visitor IDs
    await Visitor.deleteMany({ _id: { $in: visitorIds } });
    await Pass.deleteMany({ visitor_id: { $in: visitorIds } });

    // Send a successful response
    res.status(200).json({ message: 'User and associated data deleted successfully' });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});


//admin delete a visitor and visitor_pass documents
app.delete('/admin/delete/visitor/:id', authenticateToken, async (req, res) => {
  try {
    const loggedInUser = await User.findOne({ _id: req.user.user_id });

    // Check user's authentication and admin role
    if (!loggedInUser || loggedInUser.login_status !== true || loggedInUser.role !== 'admin') {
      return res.status(403).send('Unauthorized: Admin access only');
    }

    // Find and delete the visitor based on the provided ID
    const deletedv = await Visitor.findByIdAndDelete(req.params.id);

    // If the visitor is not found, return a 404 response
    if (!deletedv) {
      return res.status(404).send('visitor not found');
    }
    // Get the visitor pass IDs from the deleted visitor
    const passIds = deletedv.visitor_pass_id;
    await Pass.deleteMany({ _id: { $in: passIds } });

    // Remove the deleted visitor's ID from the user's visitor_id array
    await User.updateOne(
      { _id: deletedv.user_id },
      { $pull: { visitor_id: req.params.id } }
    );

    res.status(200).json({ message: 'Visitor and associated data deleted successfully' });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
});
