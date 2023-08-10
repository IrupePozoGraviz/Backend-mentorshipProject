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
bio: {
  type: String,
  required: true,
  minLength: 2,
  maxLength: 200
  },

  likedPersons: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    isMatched: {
      type: Boolean,
      default: false,
    },
  }],
  
  matchedPersons: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    isMatched: {
      type: Boolean,
      default: false,
    },
  }],
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
  const { username, password, email, lastName, firstName, preferences, role, bio } = req.body;

  if (!validator.isEmail(email)) {
    res.status(400).json({ message: "Please enter a valid email address" });
    return;
  }
  if (username.length < 2 || username.length > 30) {
    res.status(400).json({ success: false, message: "Username must be between 2 and 30 characters" });
    return;
  }
  // Check if username already exists
  const existingUser = await User.findOne({ username: username });
  if (existingUser) {
    return res.status(400).json({ success: false, message: "Username already exists" });
  }

  //check if email already exists

  const existingEmail = await User.findOne({ email: email });
  if (existingEmail) {
    return res.status(400).json({ success: false, message: "Email already exists" });
  }

  if (password.length < 6 || password.length > 20) {
    return res.status(400).json({ success: false, message: "Password must be between 6 and 20 characters" });
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
      bio: bio
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
          bio: user.bio,
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

// get all users
app.get("/users", async (req, res) => {
  try {
    const users = await User.find();
    if (users) {
      res.status(200).json({
        success: true,
        response: users
      });
    } else {
      res.status(400).json({
        success: false,
        response: "No users found"
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

// Show current users liked persons (mentors or mentees)

app.get('/likedPersons/:userId', async (req, res) => {
  const { userId } = req.params; // Extract the userId from the URL parameters
  
  if (userId) {
    try {
      const user = await User.findById(userId).populate({
        path: 'likedPersons.user',
        select: 'firstName username preferences role bio',
      });

      if (user) {
        const likedPersons = user.likedPersons.map((likedPerson) => likedPerson.user);

        res.status(200).json({
          success: true,
          response: {
            likedPersons: likedPersons,
            firstName: user.firstName,
            username: user.username,
            preferences: user.preferences,
            role: user.role,
            bio: user.bio,
            message: "User found"
          },
        });
      } else {
        res.status(400).json({
          success: false,
          response: 'User not found',
        });
      }
    } catch (error) {
      res.status(500).json({
        success: false,
        response: error.message,
      });
    }
  } else {
    res.status(400).json({
      success: false,
      response: 'User ID not provided',
    });
  }
});

// User to be able to like another user - PATCH - update single user by id

app.patch('/likedPersons/:userId', async (req, res) => {
  const { likedUserId } = req.body; // User we want to like (use req.body in the frontend)
  const { userId } = req.params; // Extract the userId from the URL parameters

  if (userId) {
    try {
      const userToUpdate = await User.findById(userId);
      const likedUser = await User.findById(likedUserId);

      if (userToUpdate && likedUser) {
        const likedIndex = likedUser.likedPersons.findIndex(
          (likedPerson) => likedPerson.user.toString() === userId
        );
        const mutualLikedIndex = userToUpdate.likedPersons.findIndex(
          (likedPerson) => likedPerson.user.toString() === likedUserId
        );
        const shouldMatch = likedIndex !== -1 && mutualLikedIndex !== -1;

        userToUpdate.likedPersons.push({
          user: likedUserId,
          isMatched: shouldMatch,
        });

        // added logic to check if the liked user is not already in the likedPersons array
        if (mutualLikedIndex === -1) {
          const newLikedPerson = {
            user: likedUserId,
            isMatched: shouldMatch,
          };
          userToUpdate.likedPersons.push(newLikedPerson);
        }
        if (shouldMatch) {
          userToUpdate.matchedPersons.push({
            user: likedUserId,
            isMatched: true,
          });
          likedUser.matchedPersons.push({
            user: userId,
            isMatched: true,
          });
        }

        userToUpdate.matchedPersons.push(newMatchedPersonCurrentUser);
        likedUser.matchedPersons.push(newMatchedPersonLikedUser);
      }

      await userToUpdate.save();
      await likedUser.save();

      res.json(userToUpdate);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Something went wrong' });
    }
  } else {
    res.status(400).json({ error: 'User ID not provided' });
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
/*--------------------current user to be able to see their matched persons------------------------*/
app.get('/matchedPersons/:userId', async (req, res) => {
  const { userId } = req.params; // Extract the userId from the URL parameters

  try {
    const user = await User.findById(userId); // Find the user by their ID

    if (user) {
      const matchedPersons = user.matchedPersons; // Get the array of matched persons

      res.status(200).json({
        success: true,
        matchedPersons: matchedPersons,
      });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


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


// start the server

http.listen(process.env.PORT || 8080, () => {
  console.log(`Server is running on port ${process.env.PORT || 8080}`);
});