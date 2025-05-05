import { comparePassword, hashPassword } from "../helpers/authHelper.js";
import userModel from "../model/userModel.js";
import JWT from "jsonwebtoken";

export const registerController = async (req, res) => {
  try {
    const { name, email, password, phone, state, city, street, pincode } = req.body;
    
    // Validations
    if (!name) {
      return res.status(400).send({ success: false, message: "Name is Required" });
    }
    if (!email) {
      return res.status(400).send({ success: false, message: "Email is Required" });
    }
    if (!password) {
      return res.status(400).send({ success: false, message: "Password is Required" });
    }
    if (!phone) {
      return res.status(400).send({ success: false, message: "Phone no is Required" });
    }
    if (!state) {
      return res.status(400).send({ success: false, message: "State is Required" });
    }
    if (!city) {
      return res.status(400).send({ success: false, message: "City is Required" });
    }
    if (!street) {
      return res.status(400).send({ success: false, message: "Street is Required" });
    }
    if (!pincode) {
      return res.status(400).send({ success: false, message: "Pincode is Required" });
    }

    // Check if user already exist
    const existingUser = await userModel.findOne({ email });
    
    if (existingUser) {
      return res.status(409).send({
        success: false,
        message: "Email already registered, please login",
      });
    }
    
    // Hash password
    const hashedPassword = await hashPassword(password);
    
    // Save user with structured address
    const user = await new userModel({
      name,
      email,
      password: hashedPassword,
      phone,
      address: {
        state,
        city,
        street,
        pincode
      }
    }).save();
    
    res.status(201).send({
      success: true,
      message: "User registered successfully",
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        address: user.address
      }
    });
  } catch (error) {
    console.error("Registration error:", error);
    
    // Handle duplicate key errors specifically
    if (error.code === 11000) {
      return res.status(409).send({
        success: false,
        message: "Email already exists. Please use a different email.",
      });
    }
    
    res.status(500).send({
      success: false,
      message: "Error in registration",
      error: error.message
    });
  }
};

// POST LOGIN
export const loginController = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).send({
        success: false,
        message: 'Email and password are required'
      });
    }
    
    // Check user
    const user = await userModel.findOne({ email });
    
    if (!user) {
      return res.status(401).send({
        success: false,
        message: "Invalid email or password",
      });
    }
    
    // Compare password
    const match = await comparePassword(password, user.password);
    
    if (!match) {
      return res.status(401).send({
        success: false,
        message: "Invalid email or password",
      });
    }
    
    // Generate JWT token
    const token = await JWT.sign(
      { _id: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: "7d" }
    );
    
    res.status(200).send({
      success: true,
      message: "Login successful",
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        address: user.address
      },
      token,
    });
  } catch (error) {
    console.error("Login error:", error);
    
    res.status(500).send({
      success: false,
      message: "Error in login",
      error: error.message
    });
  }
};

// Test controller for protected routes
export const testController = (req, res) => {
  try {
    res.status(200).send({
      success: true,
      message: "Protected route accessed successfully"
    });
  } catch (error) {
    console.error("Test controller error:", error);
    
    res.status(500).send({
      success: false,
      message: "Error accessing protected route",
      error: error.message
    });
  }
};