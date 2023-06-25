import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import crypto from "crypto";
import bcrypt from "bcrypt";
import validator from 'validator';

import multer from 'multer';
import listEndpoints from "express-list-endpoints";
import dotenv from 'dotenv';
dotenv.config();
require('dotenv').config();

const app = express(); // Create the Express application

// Add middlewares to enable cors and json body parsing
const corsOptions = {
  origin: '*', // Allow all origins
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'], // Allow GET and POST requests
  preflightContinue: false, // Enable preflight requests
  optionsSuccessStatus: 204, // Return 204 status for successful preflight requests
};

// Middlewares
app.use(cors(corsOptions));
app.use(express.json());
app.options('*', cors())

const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/mentorship";
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.Promise = Promise;

// Defines the port the app will run on. Defaults to 8080, but can be overridden

const port = process.env.PORT || 8080;


// Socket.io logic here not used yet
const http = require('http').createServer(app);
//http.createServer(app)
// const Server = http.createServer(app);
const io = require('socket.io')(http);

io.on('connection', (socket) => {
  console.log('A user connected');

  // Handle events from the client
  socket.on('chat message', (message) => {
    console.log('Received message:', message);
    // Broadcast the message to all connected clients
    io.emit('chat message', message);
  });

  // Handle disconnections
  socket.on('disconnect', () => {
    console.log('A user disconnected');
  });
});


app.get("/", (req, res) => {
  res.send(listEndpoints(app));

});


const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    minLength: 2,
    maxLength: 30
  },
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  verified: {
    type: Boolean,
    default: false,
  },
  preferences: [{
    type: String,
    enum: ["fullstack", "frontend", "backend", "react", "javascript", "python", "java"]
  }],

  role: {
    type: String,
    enum: ["mentor", "mentee"],
  },

likedPersons : { 
 
  type: [{ id: String, isMatched: { type: Boolean, default: false } }],
  default: [],

},
  bio: {
    type: String,
    default: ''
  },
  profilePicture: {
    type: String,
    default: ''
  },
   verificationToken: {
    type: String,
    unique: true,
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString('hex')
  }
});

const User = mongoose.model("User", UserSchema);

// REGISTRATION 
app.post("/register", async (req, res) => {
  const { username, password, email, lastName, firstName, preferences, role } = req.body;

  if (!validator.isEmail(email)) {
    res.status(400).json({ message: "Please enter a valid email address" });
    return;
  }

  if (password.length < 6 || password.length > 20) {
    res.status(400).json({ success: false, message: "Password must be between 6 and 20 characters" });
    return;
  }

  try {
    const salt = bcrypt.genSaltSync();
    const verificationToken = crypto.randomBytes(16).toString("hex"); // Generate a random verification token

    const newUser = await new User({
      username: username,
      email: email,
      firstName: firstName,
      lastName: lastName,
      password: bcrypt.hashSync(password, salt),
      verificationToken: verificationToken, // Assign the verification token to the user
      preferences: preferences,
      role: role,
    }).save();

    res.status(201).json({
      success: true,
      response: newUser
    });
  } catch (e) {
    res.status(400).json({
      success: false,
      response: e,
      message: "Could not create user",
    });
  }
});



//LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({username: username})
    if (user && bcrypt.compareSync(password, user.password)) {
      res.status(200).json({
        success: true,
        response: user
      });
    } else {
      res.status(400).json({
        success: false,
        response: "Credentials do not match"
      });
    }
  } catch (e) {
    res.status(500).json({
      success: false,
      response: e
    });
  }
});

// Get a single user by id
app.get("/user/:userId", async (req, res) => {

  try {
    const user = await User.findOne({ _id: req.params.userId });
    if (user) {
      res.status(200).json({
        success: true,
        response: {
          firstName: user.firstName,
          email: user.email,
          username: user.username,
          preferences: user.preferences,
          role: user.role,
          message: "User found"
        }
      });
    } else {
      res.status(400).json({
        success: false,
        response: "User not found"
      });
    }
  } catch (e) {
    res.status(500).json({
      success: false,
      response: e
    });
  }
});



// PATCH - update single user by id

app.patch("/user/:userId", async (req, res) => {
  const { firstName, lastName, password, email, username, preference } = req.body;
  try {
const user = await User.findOneAndUpdate( {_id: req.params.userId}, {

  firstName: firstName,
  lastName: lastName,
  password: password,
  email: email,
  username: username,
  preference: preference
}, {new: true});
if (user) {
  res.status(200).json({
    success: true,
    response: user
  
  });
} else {
  res.status(400).json({
    success: false,
    response: "User not found"
  });
}
} catch (e) {
res.status(500).json({
  success: false,
  response: e
});
}
});


app.delete("/user/:userId", async (req, res) => {
  try {
    const user = await User.findOneAndDelete({ _id: req.params.userId })
    if (user) {
      res.status(200).json({
        success: true,
        response: {
          username: user.username,
          id: user._id,
          preferences: user.preferences,
          message: "User deleted"
        }
      });
    } else {
      res.status(400).json({
        success: false,
        response: "User not found"
      });
    }
  } catch (e) {
    res.status(500).json({
      success: false,
      response: e
    });
  }
});

// users - GET - get a list of users - 
//here if you are a mentor you get a list of mentees if 
//you are a mentee you get a list of mentors, 
//additionally if you want to expand on that you can show only the users with matching preferences
app.get('/users/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const user = await User.findOne({ _id: req.params.userId });
    if (!user) {
      return res.status(400).json({
        success: false,
        response: 'User not found',
      });
    }
    const users = await User.find();
    let filteredUsers;
    if (user.role === 'mentor') {
      filteredUsers = users.filter((user) => user.role === 'mentee');
    } else {
      filteredUsers = users.filter((user) => user.role === 'mentor');
    }
    const result = filteredUsers.filter((singleUser) => {
      const likedIndex = singleUser.likedPersons.findIndex(
        (likedPerson) => likedPerson.id === userId
      );
      if (likedIndex === -1) {
        return true;
      }
    });
    res.status(200).json({
      success: true,
      response: {
        users: result,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      response: error.message,
    });
  }
});


//Liked persons -to be able to match by liked persons

app.patch("/likedPersons/:userId", async (req, res) => {
  const {likedUserId} = req.body // usern som vi vill likea (använd req.body i frontend)
  const { userId } = req.params; // Extract the userId from the URL parameters

  console.log('likedUserId', likedUserId)
  console.log('userId parama', userId)
 if( userId){
  try {

    const userToUpdate = await User.findById(userId); // Find the logged-in user by their ID
    const likedUser= await User.findById(likedUserId)
    const likedIndex= likedUser.likedPersons.findIndex(likedPerson => likedPerson.id === userId)
    if (userToUpdate) {
      console.log('userToUpdate', userToUpdate)
      const shouldMatch = likedIndex !== -1? true: false
      userToUpdate.likedPersons.push({id:likedUserId, isMatched: shouldMatch}); // Add the likedUserId to the likedPersons array of the logged-in user
  
      // Save the updated user with the new likedPersons array
      const updatedUser = await userToUpdate.save();
  
      res.json(updatedUser); // Return the updated user as the response
    } else {
      res.status(404).json({error: 'User not found'})
    }
   
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Something went wrong" });
  }} else {
    res.status(404).json({error: 'User not found'})
  }
});


//Disliked persons -to be able to NOT CHOOSE A PERSON
app.patch("/dislikedPersons/:userId", async (req, res) => { 
  const {dislikedUserId} = req.body 

  console.log('dislikedUserId', dislikedUserId) 
  const loggedInUserId = req.userId; 
  const { userId } = req.params; // Extract the userId from the URL parameters
  console.log('loggedInUserId', loggedInUserId) 
  console.log('userId params', userId) 

  try {

    const userToUpdate = await User.findById(loggedInUserId); // Find the logged-in user by their ID

    // when disliking a person we want to remove that person from the likedPersons array
    

    // Save the updated user with the new dislikedPersons array
    const updatedUser = await userToUpdate.save();

    res.json(updatedUser); // Return the updated user as the response
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Something went wrong" });
  }
});

// add a GET request to match a mentor with a mentee and vice versa
// this one is not used for now
app.get("/match", async (req, res) => {
  try {
    const mentors = await User.find({ role: "mentor" }).populate("preferences");
    const mentees = await User.find({ role: "mentee" }).populate("preferences");
    const matchedPairs = matchMentorsWithMentees(mentors, mentees);
    res.status(200).json({
      success: true,
      response: {
        matchedPairs: matchedPairs,
      },
    });
  } catch (e) {
    res.status(500).json({
      success: false,
      response: e,
    });
  }
});

// Matching Logic - not used for now
const matchMentorsWithMentees = (mentors, mentees) => {
  const matchedPairs = [];

  for (const mentor of mentors) {
    let bestMatch = null;
    let maxMatchScore = -Infinity;

    for (const mentee of mentees) {
      const matchScore = calculateMatchScore(mentor.preferences, mentee.preferences);

      if (matchScore > maxMatchScore) {
        bestMatch = mentee;
        maxMatchScore = matchScore;
      }
    }

    if (bestMatch) {
      matchedPairs.push({ mentor, mentee: bestMatch });
      mentees.splice(mentees.indexOf(bestMatch), 1);
    }
  }

  return matchedPairs;
};

const calculateMatchScore = (mentorPreferences, menteePreferences) => {
  const sharedPreferences = mentorPreferences.filter(p => menteePreferences.includes(p));
  return sharedPreferences.length;
};




//  preferences - GET - get all preferences
app.get('/preferences', async (req, res) => {
  try {
    const users = await User.find();
    const preferences = users.map(user => user.preference);
    const uniquePreferences = [...new Set(preferences)];

    res.status(200).json({
      success: true,
      response: {
        preferences: uniquePreferences,
      }
    });
  } catch (e) {
    res.status(500).json({
      success: false,
      response: e
    });
  }
});


// for profile picture upload
/*We dont have a storage for it yet*/

const upload = multer({
  storage: multer.memoryStorage()
});


// Endpoint for uploading a profile picture
// Middleware for serving uploaded files
app.use('/uploads', express.static('uploads'));

// Endpoint for uploading a profile picture
app.post('/user/:userId/upload-profile-picture', upload.single('profilePicture'), async (req, res) => {
  const userId = req.params.userId;
  const profilePicture = req.file;

  if (!profilePicture) {
    return res.status(400).json({ error: 'No file provided' });
  }

  try {
    const result = await cloudinary.uploader.upload(profilePicture.path, {
      folder: 'profile-pictures',
      public_id: `user-${userId}`,
      overwrite: true
    });

    await User.findOneAndUpdate(
      { _id: userId },
      { profilePicture: result.secure_url }
    );

    res.status(200).json({
      success: true,
      message: 'Profile picture uploaded successfully',
      file: profilePicture
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload profile picture',
      error: error.message
    });
  }
});

// Endpoint for deleting a profile picture
app.delete('/user/:userId/delete-profile-picture', async (req, res) => {
  const userId = req.params.userId;

  // Update the user's profile picture in the database
  try {
    await User.findOneAndUpdate(
      { _id: userId },
      { profilePicture: null }
    );

    res.status(200).json({
      success: true,
      message: 'Profile picture deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to delete profile picture',
      error: error.message
    });
  }
});


//For user to be able to write about them selves (not used yet)
const BioSchema = new mongoose.Schema({
  message: {
    type: String,
    required: true,
    minLength: 2,
    maxLength: 200
  },
  createdAt: {
    type: Date,
    default: () => new Date()
  },
  username: {
    type: String,
    required: true
  }
});

const bio = mongoose.model("bio", BioSchema);

// Authenticate the user
const authenticateUser = async (req, res, next) => {
  const accessToken = req.header("Authorization");
  try {
    const user = await User.findOne({accessToken: accessToken});
    if (user) {
      next();
    } else {
      res.status(401).json({
        success: false,
        response: "Please log in",
        loggedOut: true
      })
    }
  } catch (e) {
    res.status(500).json({
      success: false,
      response: e
    });
  }
}

app.get("/bio", authenticateUser);
app.get("/bio", async (req, res) => {
  try {
    const accessToken = req.header("Authorization");
    const user = await User.findOne({ accessToken: accessToken })

    if (user) {
      const bio = await bio.find({ username: user._id }).sort({ createdAt: -1 }).limit(20)
      res.status(200).json({
        success: true,
        response: bio,
      });
    } else {
      res.status(401).json({
        success: false,
        response: "Please log in",
        loggedOut: true,
      });
    }
  } catch (e) {
    res.status(500).json({
      success: false,
      response: e,
      message: "Ground control... Abort Abort!",
    });
  }
});



app.get("/bio", authenticateUser);
app.get("/bio", async (req, res) => {
  try {
    const accessToken = req.header("Authorization");
    const user = await User.findOne({ accessToken: accessToken })

    if (user) {
      const bio = await bio.find({ username: user._id }).sort({ createdAt: -1 }).limit(20)
      res.status(200).json({
        success: true,
        response: bio,
      });
    } else {
      res.status(401).json({
        success: false,
        response: "Please log in",
        loggedOut: true,
      });
    }
  } catch (e) {
    res.status(500).json({
      success: false,
      response: e,
      message: "Ground control... Abort Abort!",
    });
  }
});

app.post("/bio", authenticateUser);
app.post("/bio", async (req, res) => {
  try {
    const { message } = req.body;
    const accessToken = req.header("Authorization");
    const user = await User.findOne({accessToken: accessToken});
    const bio = await new bio({
      message: message, 
      username: user._id
    }).save();
    res.status(201).json({
      success: true, 
      response: bio
    })
  } catch (e) {
    res.status(500).json({
      success: false, 
      response: e, 
      message: "nope get out"
    });
  }
})

app.put("/bio", authenticateUser);
app.put("/bio", async (req, res) => {
  try {
    const { message } = req.body;
    const accessToken = req.header("Authorization");
    const user = await User.findOne({accessToken: accessToken});
    
    // Find and update the bio, returning the updated bio
    const updatedBio = await bio.findOneAndUpdate(
      { username: user._id }, // Find bio by user's _id
      { message: message }, // Update the message
      { new: true } // Option to return the updated document
    );
    
    if (!updatedBio) {
      return res.status(404).json({
        success: false, 
        response: "Bio not found", 
      });
    }
    
    res.status(200).json({
      success: true, 
      response: updatedBio
    });
    
  } catch (e) {
    res.status(500).json({
      success: false, 
      response: e, 
      message: "An error occurred"
    });
  }
});



// start the server

http.listen(process.env.PORT || 8080, () => {
  console.log(`Server is running on port ${process.env.PORT || 8080}`);
});