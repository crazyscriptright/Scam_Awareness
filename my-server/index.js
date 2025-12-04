// Load environment variables using custom loader
const { loadEnvironment } = require("./envLoader");
loadEnvironment();

const express = require("express");
const multer = require("multer");
const { Pool } = require("pg");
const cors = require("cors");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const morgan = require("morgan");
const compression = require("compression");
const bcrypt = require("bcrypt");
const asyncHandler = require("express-async-handler");
const { generateToken, verifyToken, requireAdmin, requireExternal, requireAuth } = require("./middleware/auth");


const app = express();
const port = process.env.PORT || 5000;
const saltRounds = 10;

const failedAttempts = {}; // { email: { count: 0, lastAttempt: Date } }

// PostgreSQL Connection (Port 5434)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  // Force UTC timezone for all connections
  options: '-c timezone=UTC',
});

// Middleware
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : ["http://localhost:3000", "https://scam-awareness.vercel.app"];

app.use(cors({ 
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow credentials (cookies, authorization headers, etc.)
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  exposedHeaders: ['Content-Length', 'X-Requested-With'],
  maxAge: 86400 // Cache preflight request for 24 hours
}));
app.use(bodyParser.json({ limit: "15mb" })); // Adjust if needed
app.use(bodyParser.urlencoded({ limit: "15mb", extended: true }));

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false // Disable for API server
}));

app.use(compression());
app.use(morgan("combined"));

// Handle OPTIONS requests for CORS preflight
app.options('*', cors());

// Multer setup (file handling, restricting to images and PDFs)
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Health check endpoint
app.get("/", (req, res) => {
  res.json({ 
    status: "ok", 
    message: "Scam Awareness API is running",
    environment: process.env.NODE_ENV || "development",
    timestamp: new Date().toISOString()
  });
});

// API root endpoint
app.get("/api", (req, res) => {
  res.json({ 
    message: "Scam Awareness API v1.0",
    endpoints: {
      auth: ["/signin", "/register", "/forgot-password", "/api/verify-token"],
      user: ["/profile", "/scam-reports", "/api/contact"],
      admin: ["/api/users/*", "/api/scam-reports", "/admin-approval/:id"],
      external: ["/external-profile-picture", "/api/scam-reports-modified"]
    }
  });
});


// TOKEN VERIFICATION ENDPOINT (replaces /session)
app.get("/api/verify-token", verifyToken, (req, res) => {
  res.json({
    valid: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      userType: req.user.userType,
      name: req.user.name,
      role: req.user.role
    }
  });
});

// Legacy /session endpoint for backward compatibility
app.get("/session", verifyToken, (req, res) => {
  res.json({
    loggedIn: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      userType: req.user.userType,
      name: req.user.name
    },
    redirectUrl: req.user.userType === 1 
      ? "/Admin/AdminHome" 
      : req.user.userType === 2 
      ? "/ExternalResources/ExternalResourcesHome" 
      : "/"
  });
});

app.get("/api/userid_fetch", verifyToken, (req, res) => {
  res.json({ user_id: req.user.id });
});

// REGISTER USER
app.post(
  "/register",
  asyncHandler(async (req, res) => {
    try {
      const { name, dob, email, password } = req.body;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      await pool.query(
        "INSERT INTO users (name, dob, email, password) VALUES ($1, $2, $3, $4)",
        [name, dob, email, hashedPassword]
      );

      res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ error: "User already registered" });
    }
  })
);

// LOGIN USER (Updated for JWT)
app.post(
  "/signin",
  asyncHandler(async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
      }

      // Check if the user is temporarily blocked
      if (failedAttempts[email] && failedAttempts[email].count >= 3) {
        const timeElapsed = (Date.now() - failedAttempts[email].lastAttempt) / 1000;
        if (timeElapsed < 300) { // 5-minute block
          return res.status(403).json({ error: "Too many failed attempts. Try again later." });
        } else {
          delete failedAttempts[email]; // Reset if timeout is over
        }
      }

      // Fetch user from the database
      const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

      if (result.rows.length === 0 || !(await bcrypt.compare(password, result.rows[0].password))) {
        // Increment failed login attempts
        if (!failedAttempts[email]) {
          failedAttempts[email] = { count: 1, lastAttempt: Date.now() };
        } else {
          failedAttempts[email].count += 1;
          failedAttempts[email].lastAttempt = Date.now();
        }

        return res.status(401).json({ error: "Invalid credentials" });
      }

      const user = result.rows[0];

      // Check user status
      if (user.status === "banned") {
        return res.status(403).json({ error: "Your account is banned. Please contact the admin." });
      }

      if (user.status !== "active") {
        return res.status(403).json({ error: "Your account is not active. Please contact the admin." });
      }

      // Successful login: reset failed attempts
      delete failedAttempts[email];

      // Generate JWT token
      const token = generateToken(user);

      const redirectUrl =
        user.usertype === 1
          ? "/Admin/AdminHome"
          : user.usertype === 2
          ? "/ExternalResources/ExternalResourcesHome"
          : "/";

      res.json({
        success: true,
        message: "Login successful",
        token: token,
        user: {
          id: user.user_id,
          name: user.name,
          email: user.email,
          userType: user.usertype
        },
        userName: user.name,
        redirectUrl,
      });
    } catch (error) {
      console.error("Sign-in error:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  })
);

// FORGOT PASSWORD
app.post(
  "/forgot-password",
  asyncHandler(async (req, res) => {
    try {
      const { email, dob, newPassword } = req.body;
      const result = await pool.query(
        "SELECT * FROM users WHERE email = $1 AND dob = $2",
        [email, dob]
      );

      if (result.rows.length > 0) {
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        await pool.query("UPDATE users SET password = $1 WHERE email = $2", [
          hashedPassword,
          email,
        ]);
      }

      res
        .status(200)
        .json({ message: "If the email exists, a reset link will be sent" });
    } catch (error) {
      console.error("Forgot password error:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  })
);

//########Scam reports########

app.post(
  "/scam-reports",
  verifyToken, // JWT authentication
  asyncHandler(async (req, res) => {
    try {
      const user_id = req.user.id;
      const { scam_type, description, scam_date, proof } = req.body;

      if (!user_id || !scam_type || !description || !scam_date || !proof) {
        return res.status(400).json({ error: "All fields are required" });
      }

      const result = await pool.query(
        "INSERT INTO scam_reports (user_id, scam_type, description, scam_date, proof) VALUES ($1, $2, $3, $4, $5) RETURNING *",
        [user_id, scam_type, description, scam_date, proof]
      );

      res.status(201).json({
        message: "Scam report submitted successfully",
        report: result.rows[0],
      });
    } catch (error) {
      console.error("Scam report submission error:", error);
      res.status(500).json({ error: "Error submitting scam report" });
    }
  })
);


// ###########User########## 
//  PROFILE User (GET & UPDATE) - No redirect on missing auth
app.get("/profile", async (req, res) => {
  try {
    // Check for authorization header
    const authHeader = req.headers.authorization;
    
    // If no token, return not authenticated (don't throw 401)
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(200).json({ authenticated: false, user: null });
    }

    // Extract and verify token
    const token = authHeader.split(' ')[1];
    const jwt = require('jsonwebtoken');
    
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      // Invalid token, return not authenticated
      return res.status(200).json({ authenticated: false, user: null });
    }

    // Fetch user profile
    const result = await pool.query(
      "SELECT name, email, profile_picture FROM users WHERE user_id = $1 AND usertype = 0",
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(200).json({ authenticated: false, user: null });
    }

    res.json({ 
      authenticated: true, 
      user: result.rows[0] 
    });
  } catch (error) {
    console.error("User profile error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Update Profile Picture
app.post(
  "/update-profile-picture",
  verifyToken,
  upload.single("profilePicture"),
  asyncHandler(async (req, res) => {
    try {
      const profilePic = req.file ? req.file.buffer : null;
      await pool.query(
        "UPDATE users SET profile_picture = $1 WHERE user_id = $2",
        [profilePic, req.user.id]
      );
      res.json({ profilePic: `data:image/jpeg;base64,${profilePic.toString('base64')}` });
    } catch (error) {
      console.error("Profile picture update error:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  })
);


// Update Password
app.post(
  "/update-password",
  verifyToken,
  asyncHandler(async (req, res) => {
    try {
      const { newPassword } = req.body;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
      await pool.query(
        "UPDATE users SET password = $1 WHERE user_id = $2",
        [hashedPassword, req.user.id]
      );
      res.json({ message: "Password updated successfully" });
    } catch (error) {
      console.error("Password update error:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  })
);


// Fetch Scam Reports for Logged-in User
app.get(
  "/scam-reports",
  asyncHandler(async (req, res) => {
    try {
      if (!req.user || !req.user.id) {
        return res.status(401).json({ error: "Unauthorized: Please log in" });
      }

      const userId = req.user.id; // Ensure req.user contains the authenticated user's ID
      const result = await pool.query("SELECT * FROM scam_reports WHERE user_id = $1", [userId]);

      res.status(200).json(result.rows);
    } catch (error) {
      console.error("Error retrieving scam reports:", error);
      res.status(500).json({ error: "Error retrieving scam reports" });
    }
  })
);

app.get("/api/reports", verifyToken, async (req, res) => {
  try {
    const user_id = req.user.id; // Fetch user_id from JWT token

    const query = `
      SELECT 
        sr.report_id,
        sr.scam_type,
        sr.description,
        sr.report_status,
        sr.submitted_at,
        sr.admin_comments
      FROM scam_reports sr
      WHERE sr.user_id = $1
      ORDER BY sr.submitted_at DESC
    `;
    const { rows } = await pool.query(query, [user_id]);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching reports:", err);
    res.status(500).json({ error: "Failed to fetch reports" });
  }
});
//#########Admin############
// GET Profile Picture with Authentication
app.get("/profile-picture", verifyToken, requireAdmin, async (req, res) => {
  try {
    const userId = req.user.id; // Remove array brackets
    const result = await pool.query(
      "SELECT profile_picture, name FROM users WHERE user_id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const userData = result.rows[0];
    res.json({
      name: userData.name,
      profile_picture: userData.profile_picture 
        ? userData.profile_picture.toString("base64")
        : null
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error." });
  }
});

// POST Profile Picture with Authentication
app.post("/profile-picture", verifyToken, requireAdmin, async (req, res) => {
  try {
    const userId = req.user.id; // Remove array brackets
    const { profile_picture } = req.body;

    if (!profile_picture) {
      return res.status(400).json({ message: "No image data provided." });
    }

    const imageBuffer = Buffer.from(profile_picture, "base64");
    await pool.query(
      "UPDATE users SET profile_picture = $1 WHERE user_id = $2",
      [imageBuffer, userId]
    );

    res.json({ message: "Profile picture uploaded successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error." });
  }
});


//##########Admin Dashboard ##########

// USER REGISTRATION
// Endpoint to get total user registrations
app.get("/api/users/total-registrations-count", verifyToken, requireAdmin, async (req, res) => {
  try {
    // Query the database to count total users
    const result = await pool.query("SELECT COUNT(*) AS total FROM users");
    
    // Extract the total count from the query result
    const totalRegistrations = result.rows[0].total;

    // Send the response
    res.status(200).json({ totalRegistrations });
  } catch (error) {
    console.error("Error fetching total registrations count:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// ACTIVE SESSIONS
app.get("/api/users/active-sessions", verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT COUNT(*) AS "activeSessions" FROM session WHERE expire > NOW()'
    );

    res.json({
      activeSessions: parseInt(result.rows[0].activeSessions, 10),
    });
  } catch (err) {
    console.error("Error fetching active sessions:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


// SECURITY ALERTS
app.get("/api/User/security-alerts", verifyToken, requireAdmin, (req, res) => {
  const alerts = Object.keys(failedAttempts)
    .filter((email) => failedAttempts[email].count >= 3) // Show only blocked users
    .map((email) => ({
      message: `Multiple failed login attempts detected for ${email}`,
      timestamp: new Date(failedAttempts[email].lastAttempt).toLocaleString(),
    }));

  res.json(alerts.length > 0 ? alerts : [{ message: "No active security alerts" }]);
});

//charts used
// USER REGISTRATION STATS
app.get("/api/users/registration-stats", verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DATE(created_at) AS date, COUNT(*) AS count 
      FROM users 
      GROUP BY DATE(created_at) 
      ORDER BY date;
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching registration stats:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// SCAM REPORTS STATS
app.get("/api/users/scam-reports", verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT scam_type, report_status 
      FROM scam_reports
      ORDER BY submitted_at DESC;
    `);
    
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("Error fetching scam reports:", error);
    res.status(500).json({ message: "Server Error", error });
  }
});


//###########Table############
// Fetch proof for a specific report
app.get("/api/scam-reports/:report_id/proof", verifyToken, async (req, res) => {
  const { report_id } = req.params;
  try {
    const result = await pool.query(
      "SELECT proof FROM scam_reports WHERE report_id = $1",
      [report_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Proof not found" });
    }

    // Return the proof as a base64-encoded string
    const proof = result.rows[0].proof;
    res.status(200).send(proof); // Send the raw base64 string
  } catch (error) {
    console.error("Error fetching proof:", error);
    res.status(500).json({ message: "Server Error", error });
  }
});

// Get all scam reports from the "submitted_scam_reports" view
app.get("/api/scam-reports", verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM submitted_scam_reports");
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching scam reports:", error);
    res.status(500).json({ error: "Error fetching scam reports" });
  }
});

// Update scam report status
app.put("/admin-approval/:report_id", verifyToken, requireAdmin, async (req, res) => {
  const { report_id } = req.params;
  const { report_status, admin_comments } = req.body;

  if (!report_status) {
    return res.status(400).json({ error: "report_status is required" });
  }

  try {
    const result = await pool.query(
      "UPDATE scam_reports SET report_status = $1, admin_comments = $2 WHERE report_id = $3 RETURNING *",
      [report_status, admin_comments || null, report_id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Report not found" });
    }

    res.json({ message: "Report updated successfully", report: result.rows[0] });
  } catch (error) {
    console.error("Error updating report:", error);
    res.status(500).json({ error: "Error updating report" });
  }
});


// API to create a new entry in external_resources table
app.post("/external-resources-status-update", verifyToken, requireAdmin, async (req, res) => {
  const { verification_id, report_status } = req.body;

  try {
    const query = `
      INSERT INTO external_resources (verification_id, report_status)
      VALUES ($1, $2)
      RETURNING *;
    `;
    const values = [verification_id, report_status];

    const result = await pool.query(query, values);

    res.status(201).json({ message: "External resource created successfully", data: result.rows[0] });
  } catch (error) {
    console.error("Error creating external resource:", error);
    res.status(500).json({ error: "Failed to create external resource" });
  }
});

//#########Fetch all scam reports##########
// Fetch all scam reports
app.get("/api/all-scam-reports", verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        report_id, 
        user_id, 
        scam_type, 
        scam_date, 
        report_status, 
        last_modified, 
        description 
      FROM scam_reports
      ORDER BY last_modified DESC;
    `);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("Error fetching all scam reports:", error);
    res.status(500).json({ message: "Server Error", error });
  }
});


//##############Creating External Users##############
//createing external users
app.post("/api/create_external_user", verifyToken, requireAdmin, async (req, res) => {
  const { name, dob, email, password } = req.body;

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert user into the database with hashed password
    const result = await pool.query(
      `INSERT INTO users (name, dob, email, password, usertype)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name, dob, email, hashedPassword, 2] // user_type is set to 2
    );

    res.status(201).json({ message: "User created successfully", user: result.rows[0] });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ message: "Failed to create user", error });
  }
});


//###########Contact##########
// Fetch all contact details
app.get("/api/contacts", verifyToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        contact_id, 
        user_id, 
        message, 
        submitted_at, 
        attachment 
      FROM contacts
      ORDER BY submitted_at DESC;
    `);

    res.status(200).json(result.rows);
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).json({ message: "Failed to fetch contacts", error });
  }
});

//###########User staus block ##########
// Update user status by email or ID
app.put("/api/users/status", verifyToken, requireAdmin, async (req, res) => {
  const { identifier, status } = req.body;

  try {
    // Check if the identifier is a number (user ID) or a string (email)
    const isNumeric = !isNaN(identifier);

    const result = await pool.query(
      `UPDATE users 
       SET status = $1 
       WHERE ${isNumeric ? "user_id = $2::integer" : "email = $2"} 
       RETURNING *`,
      [status, identifier]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error("Error updating user status:", error);
    res.status(500).json({ message: "Failed to update user status", error });
  }
});


//###########Normal user###############
// Contact Us or Feedback
// Contact Us endpoint
app.post("/api/contact", verifyToken, (req, res) => {
  const { message, attachment } = req.body;

  // Check if user is logged in
  if (!req.user || !req.user.id) {
    return res.status(401).json({ error: "Unauthorized: Please log in" });
  }

  const userId = req.user.id; // Get user_id from JWT token

  // Insert into database
  pool.query(
    "INSERT INTO contacts (user_id, message, attachment, submitted_at) VALUES ($1, $2, $3, $4) RETURNING *",
    [userId, message, attachment, new Date()],
    (error, result) => {
      if (error) {
        console.error("Error inserting contact:", error);
        return res.status(500).json({ error: "Internal Server Error" });
      }
      res.status(201).json(result.rows[0]);
    }
  );
});

app.get("/api/contacts/:contact_id/attachment", verifyToken, async (req, res) => {
  const { contact_id } = req.params;

  try {
    const result = await pool.query(
      "SELECT attachment FROM contacts WHERE contact_id = $1",
      [contact_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Contact not found" });
    }

    const attachment = result.rows[0].attachment;

    // If the attachment is a base64-encoded string, send it directly
    res.status(200).send(attachment);
  } catch (error) {
    console.error("Error fetching attachment:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post(
  "/contact",
  verifyToken,
  asyncHandler(async (req, res) => {
    try {
      const { message, attachment } = req.body;
      const user_id = req.user.id;

      if (!message) {
        return res.status(400).json({ error: "Message field is required" });
      }

      const result = await pool.query(
        "INSERT INTO contacts (user_id, message, attachment) VALUES ($1, $2, $3) RETURNING *",
        [user_id, message, attachment || null]
      );

      res.status(201).json({
        message: "Contact request submitted successfully",
        contact: result.rows[0],
      });
    } catch (error) {
      console.error("Contact form submission error:", error);
      res.status(500).json({ error: "Error submitting contact request" });
    }
  })
);
app.get("/api/contacts", verifyToken, requireAdmin, async (req, res) => {
  try {
    const { limit = 10, offset = 0 } = req.query; // Defaults to fetching 10 records
    const result = await pool.query(
      "SELECT contact_id, user_id, message, submitted_at, encode(attachment, 'base64') as attachment FROM contacts ORDER BY submitted_at DESC LIMIT $1 OFFSET $2",
      [limit, offset]
    );
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("Error fetching contacts:", error);
    res.status(500).json({ message: "Server Error", error });
  }
});

app.get("/download/:contact_id", verifyToken, async (req, res) => {
  const { contact_id } = req.params;

  try {
    const result = await pool.query(
      "SELECT attachment FROM contacts WHERE contact_id = $1",
      [contact_id]
    );

    if (result.rows.length === 0 || !result.rows[0].attachment) {
      return res.status(404).json({ message: "Attachment not found" });
    }

    const fileData = result.rows[0].attachment; // BYTEA data

    res.set({
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="attachment_${contact_id}"`,
    });

    res.send(fileData); // Send raw file data
  } catch (error) {
    console.error("Error downloading file:", error);
    res.status(500).json({ message: "Server Error", error });
  }
});

// ###########External resource#############
// External profile picture
app.get("/external-profile-picture", verifyToken, requireExternal, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      "SELECT profile_picture, name FROM users WHERE user_id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    const userData = result.rows[0];
    res.json({
      name: userData.name,
      profile_picture: userData.profile_picture 
        ? userData.profile_picture.toString("base64")
        : null
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error." });
  }
});

// POST Profile Picture with Authentication
app.post("/external-profile-picture", verifyToken, requireExternal, async (req, res) => {
  try {
    const userId = req.user.id;
    const { profile_picture } = req.body;

    if (!profile_picture) {
      return res.status(400).json({ message: "No image data provided." });
    }

    const imageBuffer = Buffer.from(profile_picture, "base64");
    await pool.query(
      "UPDATE users SET profile_picture = $1 WHERE user_id = $2",
      [imageBuffer, userId]
    );

    res.json({ message: "Profile picture uploaded successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error." });
  }
});

//modifed all scam reports
app.get("/api/all-scam-reports-modified", verifyToken, requireExternal, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
          report_id, 
          user_id, 
          scam_type, 
          scam_date, 
          report_status, 
          last_modified, 
          description 
      FROM scam_reports
      WHERE report_status NOT IN ('Submitted', 'Pending', 'Cancelled')
      ORDER BY last_modified DESC;
    `);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error("Error fetching all scam reports:", error);
    res.status(500).json({ message: "Server Error", error });
  }
});

//external status update
// Get all scam reports from the "submitted_scam_reports not cancelled or Resolved or " view
app.get("/api/scam-reports-modified", verifyToken, requireExternal, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
          report_id, 
          user_id, 
          scam_type, 
          scam_date, 
          report_status, 
          last_modified, 
          description,
          proof 
      FROM scam_reports
      WHERE report_status IN ('In Progress',
        'Waiting for Update',
        'Under Review',
        'Escalated',
        'On Hold')
      ORDER BY last_modified DESC;
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching scam reports:", error);
    res.status(500).json({ error: "Error fetching scam reports" });
  }
});

// Update scam report status
app.put("/external-report-update/:report_id", verifyToken, requireExternal, async (req, res) => {
  const { report_id } = req.params;
  const { report_status, admin_comments } = req.body;

  if (!report_status) {
    return res.status(400).json({ error: "report_status is required" });
  }

  try {
    const result = await pool.query(
      "UPDATE scam_reports SET report_status = $1, admin_comments = $2 WHERE report_id = $3 RETURNING *",
      [report_status, admin_comments || null, report_id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Report not found" });
    }

    res.json({ message: "Report updated successfully", report: result.rows[0] });
  } catch (error) {
    console.error("Error updating report:", error);
    res.status(500).json({ error: "Error updating report" });
  }
});

// NEWS API PROXY - Fetch news articles from News API
app.get("/api/news", async (req, res) => {
  try {
    const { q, pageSize = 20, language = 'en', sortBy = 'publishedAt' } = req.query;
    
    if (!q) {
      return res.status(400).json({ error: "Query parameter 'q' is required" });
    }

    // Check if NEWS_API_KEY is configured
    const newsApiKey = process.env.NEWS_API_KEY;
    if (!newsApiKey) {
      console.warn("NEWS_API_KEY not configured");
      return res.status(200).json({ 
        status: 'ok',
        articles: [],
        totalResults: 0,
        message: "News service temporarily unavailable"
      });
    }

    // Use native https module with proper headers
    const https = require('https');
    const url = new URL(`https://newsapi.org/v2/everything`);
    url.searchParams.append('q', q);
    url.searchParams.append('pageSize', pageSize);
    url.searchParams.append('language', language);
    url.searchParams.append('sortBy', sortBy);
    url.searchParams.append('apiKey', newsApiKey);
    
    // Make request to News API with User-Agent header
    const options = {
      hostname: 'newsapi.org',
      path: url.pathname + url.search,
      method: 'GET',
      headers: {
        'User-Agent': 'ScamAwareness/1.0 (https://scam-awareness.vercel.app)',
        'Accept': 'application/json'
      }
    };

    const response = await new Promise((resolve, reject) => {
      const apiReq = https.request(options, (apiRes) => {
        let data = '';
        apiRes.on('data', chunk => data += chunk);
        apiRes.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error('Invalid JSON response from News API'));
          }
        });
      });
      
      apiReq.on('error', reject);
      apiReq.end();
    });

    // Forward the response from News API
    if (response.status === 'ok') {
      res.json(response);
    } else {
      console.error("News API error:", response);
      // Return empty articles array instead of error to allow fallback on frontend
      res.status(200).json({ 
        status: 'ok',
        articles: [],
        totalResults: 0,
        message: response.message || "News service temporarily unavailable"
      });
    }
  } catch (error) {
    console.error("News API proxy error:", error);
    // Return empty articles array instead of error to allow fallback on frontend
    res.status(200).json({ 
      status: 'ok',
      articles: [],
      totalResults: 0,
      message: "News service temporarily unavailable"
    });
  }
});

// LOGOUT
// JWT is stateless, so logout is handled client-side by removing the token
// This endpoint is optional and mainly for confirmation
app.post("/logout", (req, res) => {
  res.status(200).json({ 
    success: true, 
    message: "Logged out successfully. Please remove the token from client storage." 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: "Endpoint not found",
    path: req.path,
    method: req.method
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Error:", err);
  
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ 
      error: "CORS policy violation",
      message: "Origin not allowed" 
    });
  }
  
  res.status(err.status || 500).json({ 
    error: err.message || "Internal Server Error",
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// Start the server
app.listen(port, () => {
  console.log(`✅ Server running on http://localhost:${port}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔐 CORS enabled for: ${allowedOrigins.join(', ')}`);
});