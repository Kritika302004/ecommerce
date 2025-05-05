import JWT from 'jsonwebtoken';
import userModel from '../model/userModel.js';

// Protected route token base middleware
export const requireSignIn = async (req, res, next) => {
    try {
        // Check if authorization header exists
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).send({
                success: false,
                message: "Authorization header is missing"
            });
        }

        // Validate token format (Bearer token)
        if (!authHeader.startsWith('Bearer ')) {
            return res.status(401).send({
                success: false,
                message: "Invalid token format. Use 'Bearer [token]'"
            });
        }

        // Extract the token
        const token = authHeader.split(' ')[1];
        
        // Verify the token
        const decode = JWT.verify(token, process.env.JWT_SECRET);
        
        // Set the user in the request object
        req.user = decode;
        next();
    }
    catch(error) {
        console.log("JWT Authentication Error:", error.message);
        
        // Handle different types of JWT errors
        if (error.name === 'TokenExpiredError') {
            return res.status(401).send({
                success: false,
                message: "Token has expired"
            });
        } else if (error.name === 'JsonWebTokenError') {
            return res.status(401).send({
                success: false,
                message: "Invalid token"
            });
        } else {
            return res.status(500).send({
                success: false,
                message: "Authentication error"
            });
        }
    }
};

// Admin access middleware
export const isAdmin = async (req, res, next) => {
    try {
        // Make sure req.user exists (requireSignIn middleware was used before)
        if (!req.user || !req.user._id) {
            return res.status(401).send({
                success: false,
                message: "Authentication required"
            });
        }
        
        // Find the user by ID
        const user = await userModel.findById(req.user._id);
        
        // Check if user exists
        if (!user) {
            return res.status(404).send({
                success: false,
                message: "User not found"
            });
        }
        
        // Check if user is admin
        if (user.role !== 1) {
            return res.status(403).send({
                success: false,
                message: "Access forbidden. Admin privileges required"
            });
        }
        
        // If user is admin, proceed
        next();
    }
    catch(error) {
        console.log("Admin Check Error:", error.message);
        res.status(500).send({
            success: false,
            message: "Error in admin authorization",
            error: error.message
        });
    }
}