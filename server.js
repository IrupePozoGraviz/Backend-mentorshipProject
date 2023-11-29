import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import crypto from "crypto";
import bcrypt from "bcrypt";
import validator from 'validator';
import listEndpoints from "express-list-endpoints";
import dotenv from "dotenv";
import multer from 'multer';
import {v2 as cloudinary} from 'cloudinary';

dotenv.config();
require('dotenv').config();

const app = express(); 


// Add middlewares to enable cors and json body parsing
const corsOptions = {
  origin: '*', 
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'], 
  preflightContinue: false, 
  optionsSuccessStatus: 204, 
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

// handles pictures
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// handles pictures
const storage = multer.memoryStorage(); // this will store the file as a buffer in memory
const upload = multer({ storage: storage });



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

// endpoint used for developing and administrating purposes 
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
      const likedIndex = loggedUser.likedPersons.findIndex((u) => u.user.toString() === user._id.toString());
      const matchedIndex = loggedUser.matchedPersons.findIndex((u) => u.user.toString() === user._id.toString());
      return (user._id.toString() !== userId && user.role !== loggedUser.role && likedIndex === -1 && matchedIndex === -1);

    })

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

// Endpoint handleling matching logic

app.patch('/like/:userId', async (req, res) => {
  try {
    const { userId } = req.params; 
    
    const likedProfileId = req.body.likedUserId; 

    const userWhoLiked = await User.findById(userId); 
    
    const profileToLike = await User.findById(likedProfileId); 

    if (!userWhoLiked || !profileToLike) { 
      return res.status(404).json({ error: 'User not found' }); 
    }

    const alreadyLiked = userWhoLiked.likedPersons.findIndex( 
      (likedPerson) => likedPerson.user.toString() === likedProfileId 
    )
    if (alreadyLiked !== -1) { 
      return res.status(400).json({ error: 'User has been already liked' }); 
    }

    const userWasLiked = profileToLike.likedPersons.findIndex( 
      (likedPerson) => likedPerson.user?.toString() === userId 
    )
    if (userWasLiked !== -1) {
      userWhoLiked.matchedPersons.push({ user: likedProfileId });
      profileToLike.matchedPersons.push({ user: userId });
      profileToLike.likedPersons = profileToLike.likedPersons.filter( 
        (likedPerson) => likedPerson.user.toString() !== userId
      );
    await userWhoLiked.save();
    await profileToLike.save();
    console.log("Matched - Before Response");
    return res.status(200).json({ message: 'Matched' });
  } else {
    userWhoLiked.likedPersons.push({ user: likedProfileId });

    await userWhoLiked.save();
    console.log("No Match - Before Response"); 
    return res.status(200).json({ message: 'User liked successfully. No match yet' });
  }
} catch (error) {
  res.status(500).json({ error: 'Something went wrong' });
}
});

//Disliked persons -to be able to NOT CHOOSE A PERSON (not in use yet, but will be in nearest future)
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
  const { userId } = req.params;

  try {
    const user = await User.findById(userId).populate({
      path: 'matchedPersons.user',
      select: 'firstName username preferences role bio',
    });

    if (user) {
      const matchedPersons = user.matchedPersons.map((matchedPerson) => matchedPerson.user);

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


// Endpoint for uploading a profile picture
app.post('/user/:userId/upload-profile-picture', upload.single('profilePicture'), async (req, res) => {
  const userId = req.params.userId;
  const profilePicture = req.file;

  if (!profilePicture) {
    return res.status(400).json({ error: 'No file provided' });
  }

  // TODO: Add authorization logic here to ensure the user is allowed to upload for this userId

  try {
    const uploadResult = await new Promise((resolve, reject) => {
      cloudinary.uploader.upload_stream(
        { 
          folder: 'profile-pictures',
          public_id: `user-${userId}`,
          overwrite: true
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      ).end(profilePicture.buffer);
    });

    const updatedUser = await User.findOneAndUpdate(
      { _id: userId },
      { profilePicture: uploadResult.secure_url },
      { new: true }  // This option returns the updated document
    );

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.status(200).json({
      success: true,
      message: 'Profile picture uploaded successfully',
      file: {
        fieldname: profilePicture.fieldname,
        originalname: profilePicture.originalname,
        mimetype: profilePicture.mimetype,
        size: profilePicture.size
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload profile picture'
    });
  }
});


// Endpoint for deleting a profile picture
app.delete('/user/:userId/delete-profile-picture', async (req, res) => {
  const userId = req.params.userId;

  try {
      // Fetch the current user's profilePicture URL
      const user = await User.findById(userId);
      if (user && user.profilePicture) {
          // Extract the public_id from the secure URL
          const filename = user.profilePicture.split('/').pop().split('.')[0];

          // Delete from Cloudinary
          await cloudinary.uploader.destroy(filename);
          
          // Remove the reference from the database
          await User.findOneAndUpdate(
              { _id: userId },
              { profilePicture: '' }
          );

          res.status(200).json({
              success: true,
              message: 'Profile picture deleted successfully'
          });
      } else {
          res.status(404).json({
              success: false,
              message: 'User not found or no profile picture set'
          });
      }
  } catch (error) {
      res.status(500).json({
          success: false,
          message: 'Failed to delete profile picture',
          error: error.message
      });
  }
});

// Endpoint for getting a profile picture
// Endpoint for getting a user's profile picture
app.get('/user/:userId/profile-picture', async (req, res) => {
  const userId = req.params.userId;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if the user has a profile picture set
    if (user.profilePicture) {
      // Option 1: Redirect to the image URL
      res.redirect(user.profilePicture);

      // Option 2: Serve the image file directly (if stored locally or accessible)
      // res.sendFile('path/to/image/file');

    } else {
      res.status(404).json({ error: 'No profile picture set for this user' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve profile picture'
    });
  }
});




// start the server
http.listen(process.env.PORT || 8080, () => {
  console.log(`Server is running on port ${process.env.PORT || 8080}`);
});
