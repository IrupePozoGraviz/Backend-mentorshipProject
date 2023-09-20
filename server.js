import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import crypto from "crypto";
import bcrypt from "bcrypt";
import validator from 'validator';
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
const http = require('http').createServer(app);


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

  const existingUser = await User.findOne({ username: username });
  if (existingUser) {
    return res.status(400).json({ success: false, message: "Username already exists" });
  }

  const existingEmail = await User.findOne({ email: email });
  if (existingEmail) {
    return res.status(400).json({ success: false, message: "Email already exists" });
  }

  if (password.length < 6 || password.length > 20) {
    res.status(400).json({ success: false, message: "Password must be between 6 and 20 characters" });
    return;
  }

  try {
    const salt = bcrypt.genSaltSync();
    const verificationToken = crypto.randomBytes(16).toString("hex");

    const newUser = await new User({
      username: username,
      email: email,
      firstName: firstName,
      lastName: lastName,
      password: bcrypt.hashSync(password, salt),
      verificationToken: verificationToken,
      preferences: preferences,
      role: role,
      bio: bio
    }).save();

    res.status(201).json({
      success: true,
      response: newUser
    });
  } catch (e) {
    console.error("Error creating user:", e);
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

// Get single user by id
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


// Endpoint that enables user to update its own profile (not in use yet, but will be in nearest future)

app.patch("/user/:userId", async (req, res) => {
  const { firstName, lastName, password, email, username, preference  } = req.body;
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

// Endpoint that enables user to delete its own profile (not in use yet, but will be in nearest future)

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

// endpoint used by the developers and used for administrating reasons only
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


// Endpoint filters the mentees and mentors. Mentors see a list of mentees and vice versa.

app.get('/potentialMatches/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const loggedUser = await User.findOne({ _id: req.params.userId });
    if (!loggedUser) {
      return res.status(400).json({
        success: false,
        response: 'User not found',
      });
    }
    const users = await User.find();

    const filteredUsers = users.filter((user) => {
      // Don't show users who have already been liked by the logged-in user
      const likedIndex = loggedUser.likedPersons.findIndex((u) => u.user.toString() === user._id.toString());
      // Don't show users who have already been matched with the logged-in user
      const matchedIndex = loggedUser.matchedPersons.findIndex((u) => u.user.toString() === user._id.toString());
      // Filter out the logged-in user and users who has the same role as the current logged-in user
      return (user._id.toString() !== userId && user.role !== loggedUser.role && likedIndex === -1 && matchedIndex === -1);
    });

    res.status(200).json({
      success: true,
      response: {
        users: filteredUsers,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      response: error.message,
    });
  }
});

// Endpoint show current users liked persons (mentors or mentees)

app.get('/likedPersons/:userId', async (req, res) => {
  const { userId } = req.params;
  
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


// Ursäkta röran vi bygger om / Excuse the mess, we're working on the new Endpoint  PATCH REQUEST TO LIKE A PERSON 


/*1. if user to uppdate (Annika)likes a person then the code has to look if likedpersons(Irro)has
allready liked here as well if yes they match
(find if user to uppdate exists as liked in liked persons array if yes then match) */


/*2. men om irro inte hunnit gilla tillbaka så läggs Irro in i annikas gilla lista
if userId (loged in user/user to uppdate) doesnt exist in liked.user.likedperson array
then we add likedUser to the userto uppdate*/


/* 3. if likeduser and userTouppdate has liked eachother, we need to remove
userTouppdate form likedusers liked array and add echother to match array
*/

app.patch('/likedPersons/:userId', async (req, res) => {
  try {
    const { likedUserId } = req.body; 
    const { userId } = req.params;

    console.log('[PATCH /likedPersons/:userId] Received request to like user', likedUserId, 'by user', userId);

    const userToUpdate = await User.findById(userId);
    const likedUser = await User.findById(likedUserId);

    if (!userToUpdate || !likedUser) {
      console.error('[PATCH /likedPersons/:userId] One or both users not found.');
      return res.status(404).json({ error: 'User not found.' });
    }

    console.log('[PATCH /likedPersons/:userId] userToUpdate likedPersons:', userToUpdate.likedPersons);
    console.log('[PATCH /likedPersons/:userId] likedUser likedPersons:', likedUser.likedPersons);

    // Check if the likedUser has already liked the userToUpdate
    const foundMatch = likedUser.likedPersons.some(person => String(person.user) === String(userId));

    console.log('[PATCH /likedPersons/:userId] Match found between users:', foundMatch);

    if (foundMatch) {
      // If a match is found, add each other to their matchedPersons array
      userToUpdate.matchedPersons.push(likedUserId);
      likedUser.matchedPersons.push(userId);

      console.log('[PATCH /likedPersons/:userId] userToUpdate matchedPersons after update:', userToUpdate.matchedPersons);
      console.log('[PATCH /likedPersons/:userId] likedUser matchedPersons after update:', likedUser.matchedPersons);

      // Remove userToUpdate from likedUser's likedPersons array
      likedUser.likedPersons = likedUser.likedPersons.filter(person => String(person.user) !== String(userId));

      console.log('[PATCH /likedPersons/:userId] likedUser likedPersons after removing matched user:', likedUser.likedPersons);

      await userToUpdate.save();
      await likedUser.save();

      return res.status(200).json({ message: 'Match found and saved!' });

    } else {
      // If there's no match, just save the like
      userToUpdate.likedPersons.push({ user: likedUserId, isMatched: false });

      console.log('[PATCH /likedPersons/:userId] userToUpdate likedPersons after liking:', userToUpdate.likedPersons);

      await userToUpdate.save();

      return res.status(200).json({ message: 'User liked successfully, but no match yet.' });
    }
    
  } catch (error) {
    console.error('[PATCH /likedPersons/:userId] Error:', error.message);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Do like or match if logged-in user has been liked by liked user
app.patch('/like/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const likedProfileId = req.body.likedUserId;

    const userWhoLiked = await User.findById(userId);
    const profileToLike = await User.findById(likedProfileId);

    if (!userWhoLiked || !profileToLike) {
      return res.status(404).json({ error: 'User not found' });
    }

    // If the user who initiated the like already like the profile to like
    const alreadyLiked = userWhoLiked.likedPersons.findIndex(
      (likedPerson) => likedPerson.user.toString() === likedProfileId
    )
    if (alreadyLiked !== -1) {
      return res.status(400).json({ error: 'User has been already liked' });
    }

    // First check if user who initiated the like was already liked by 'the profile to like'
    const userWasLiked = profileToLike.likedPersons.findIndex(
      (likedPerson) => likedPerson.user?.toString() === userId
    )
    // User who initiated the like was already liked by the 'profile to like'
    if (userWasLiked !== -1) {
      // Match both users
      userWhoLiked.matchedPersons.push({ user: likedProfileId }); // you need to specify the user object
      profileToLike.matchedPersons.push({ user: userId }); // add userId not a user object

      // Remove the user who initiated the like from the profile to like's likedPersons array
      profileToLike.likedPersons = profileToLike.likedPersons.filter(
        (likedPerson) => likedPerson.user.toString() !== userId
      );
    }
    // User who initiated the like has not been liked by the profile to like
    else {
      userWhoLiked.likedPersons.push({ user: likedProfileId });
    }

    await userWhoLiked.save();
    await profileToLike.save();

    // Respond with a success message
    res.status(200).json({ message: 'User liked successfully.' });
  } catch {
    res.status(500).json({ error: 'Something went wrong' });
  }
});

//Endpoint that enables user to dislike another profile (not in use yet, but will be in nearest future)
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

//Endpoint current user to be able to see their matched persons
app.get('/matchedPersons/:userId', async (req, res) => {
  const { userId } = req.params; // Extract the userId from the URL parameters

  try {
    const user = await User.findById(userId).populate({
      path: 'matchedPersons.user',
      select: 'firstName username preferences role bio',
    }); // Find the user by their ID and populate the matchedPersons array with the user objects

    if (user) {
      const matchedPersons = user.matchedPersons.map((matchedPerson) => matchedPerson.user); // Get the array of matched persons

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

// start the server

http.listen(process.env.PORT || 8080, () => {
  console.log(`Server is running on port ${process.env.PORT || 8080}`);
});
