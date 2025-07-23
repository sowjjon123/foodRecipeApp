const jwt = require("jsonwebtoken"); // Make sure jwt is imported

const verifyToken = (req, res, next) => {
    let token = req.headers["authorization"];

    if (!token) {
        // If no token is provided, return 401 Unauthorized.
        return res.status(401).json({ message: "Access Denied: No token provided." });
    }

    // Tokens are usually sent as "Bearer <YOUR_TOKEN>", so split to get the token part.
    token = token.split(" ")[1];

    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
        if (err) {
            // Log the specific JWT error for debugging on the server side
            console.error("JWT verification failed:", err);

            // Handle different types of JWT errors
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ message: "Access Denied: Token expired. Please log in again." });
            }
            // For any other verification error (e.g., invalid signature), return 403 Forbidden.
            // This is a more appropriate status code for an invalid token than 400.
            return res.status(403).json({ message: "Access Denied: Invalid token." });
        } else {
            // If verification is successful, attach the decoded payload to req.user
            // The decoded object should contain { email, id: userId } as signed in userSignUp
            console.log("Decoded JWT payload:", decoded);
            req.user = decoded;
            // Proceed to the next middleware or route handler (e.g., addRecipe)
            next();
        }
    });
};

module.exports = verifyToken; // Ensure this is the correct export for your auth middleware file