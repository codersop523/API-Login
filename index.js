const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

/* ==============================
   FIREBASE INITIALIZATION
============================== */

let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else {
  serviceAccount = require("./serviceAccountKey.json");
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

/* ==============================
   JWT SECRET
============================== */

const JWT_SECRET =
  process.env.JWT_SECRET || "your-super-secret-key-change-in-production";

/* ==============================
   ADMIN LOGIN API
============================== */

app.post("/adminLogin", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: "Email and password required",
      });
    }

    const adminsRef = db.collection("admins");
    const adminQuery = await adminsRef.where("email", "==", email).get();

    // ❌ USER NOT FOUND
    if (adminQuery.empty) {
      return res.status(401).json({
        success: false,
        error: "Invalid email or password",
      });
    }

    // ✅ EXISTING ADMIN
    const existingAdmin = adminQuery.docs[0];
    const adminData = existingAdmin.data();

    const isPasswordValid = await bcrypt.compare(
      password,
      adminData.password
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        error: "Invalid email or password",
      });
    }

    const adminId = existingAdmin.id;

    const adminDoc = {
      id: adminId,
      email: adminData.email,
      role: adminData.role || "admin",
    };

    const token = jwt.sign(
      { adminId, email: adminDoc.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      message: "Login successful",
      token,
      admin: adminDoc,
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: "Server error",
    });
  }
});

/* ==============================
   HEALTH CHECK
============================== */

app.get("/", (req, res) => {
  res.send("Admin Auth API running");
});

/* ==============================
   SERVER START
============================== */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});