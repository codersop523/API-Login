const functions = require("firebase-functions");
const admin = require("firebase-admin");
const cors = require("cors")({origin: true});
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

admin.initializeApp();
const db = admin.firestore();

const JWT_SECRET =
  process.env.JWT_SECRET || "your-super-secret-key-change-in-production";

// ============================================
// 🔐 ADMIN LOGIN API
// ============================================
exports.adminLogin = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({
          success: false,
          error: "Method not allowed. Use POST.",
        });
      }

      const {email, password} = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          error: "Email and password are required",
        });
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if (!emailRegex.test(email)) {
        return res.status(400).json({
          success: false,
          error: "Invalid email format",
        });
      }

      const adminsRef = db.collection("admins");
      const adminQuery = await adminsRef.where("email", "==", email).get();

      let adminDoc;
      let adminId;
      let isNewAdmin = false;

      if (adminQuery.empty) {
        const hashedPassword = await bcrypt.hash(password, 10);

        const newAdminRef = await adminsRef.add({
          email,
          password: hashedPassword,
          name: email.split("@")[0],
          role: "admin",
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          lastLogin: admin.firestore.FieldValue.serverTimestamp(),
          loginCount: 1,
        });

        adminId = newAdminRef.id;

        adminDoc = {
          id: adminId,
          email,
          name: email.split("@")[0],
          role: "admin",
        };

        isNewAdmin = true;
      } else {
        const existingAdmin = adminQuery.docs[0];
        adminId = existingAdmin.id;

        const adminData = existingAdmin.data();

        const isPasswordValid = await bcrypt.compare(
            password,
            adminData.password,
        );

        if (!isPasswordValid) {
          return res.status(401).json({
            success: false,
            error: "Invalid credentials",
          });
        }

        await adminsRef.doc(adminId).update({
          lastLogin: admin.firestore.FieldValue.serverTimestamp(),
          loginCount: admin.firestore.FieldValue.increment(1),
        });

        adminDoc = {
          id: adminId,
          email: adminData.email,
          name: adminData.name || email.split("@")[0],
          role: adminData.role || "admin",
        };
      }

      const token = jwt.sign(
          {
            adminId,
            email: adminDoc.email,
            role: adminDoc.role,
          },
          JWT_SECRET,
          {
            expiresIn: "7d",
          },
      );

      return res.status(200).json({
        success: true,
        message: isNewAdmin ?
          "Admin account created successfully" :
          "Login successful",
        isNewAdmin,
        data: {
          token,
          admin: adminDoc,
        },
      });
    } catch (error) {
      console.error("Login error:", error);

      return res.status(500).json({
        success: false,
        error: "Internal server error",
        details: error.message,
      });
    }
  });
});

// ============================================
// 🔍 VERIFY TOKEN API
// ============================================
exports.verifyAdminToken = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({
          success: false,
          error: "Method not allowed. Use POST.",
        });
      }

      const {token} = req.body;

      if (!token) {
        return res.status(400).json({
          success: false,
          error: "Token is required",
        });
      }

      const decoded = jwt.verify(token, JWT_SECRET);

      const adminSnap = await db
          .collection("admins")
          .doc(decoded.adminId)
          .get();

      if (!adminSnap.exists) {
        return res.status(401).json({
          success: false,
          error: "Admin not found",
        });
      }

      const adminData = adminSnap.data();

      return res.status(200).json({
        success: true,
        message: "Token is valid",
        data: {
          admin: {
            id: adminSnap.id,
            email: adminData.email,
            name: adminData.name,
            role: adminData.role,
          },
        },
      });
    } catch (error) {
      if (error.name === "JsonWebTokenError") {
        return res.status(401).json({
          success: false,
          error: "Invalid token",
        });
      }

      if (error.name === "TokenExpiredError") {
        return res.status(401).json({
          success: false,
          error: "Token expired",
        });
      }

      console.error("Verification error:", error);

      return res.status(500).json({
        success: false,
        error: "Internal server error",
      });
    }
  });
});

// ============================================
// 📋 GET ALL ADMINS API
// ============================================
exports.getAllAdmins = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {
    try {
      if (req.method !== "GET") {
        return res.status(405).json({
          success: false,
          error: "Method not allowed. Use GET.",
        });
      }

      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
          success: false,
          error: "No token provided",
        });
      }

      const token = authHeader.split("Bearer ")[1];

      jwt.verify(token, JWT_SECRET);

      const snapshot = await db.collection("admins").get();

      const admins = snapshot.docs.map((doc) => {
        const data = doc.data();

        return {
          id: doc.id,
          email: data.email,
          name: data.name,
          role: data.role,
          createdAt: data.createdAt,
          lastLogin: data.lastLogin,
          loginCount: data.loginCount || 0,
        };
      });

      return res.status(200).json({
        success: true,
        data: {
          admins,
          total: admins.length,
        },
      });
    } catch (error) {
      console.error("Get admins error:", error);

      return res.status(500).json({
        success: false,
        error: "Internal server error",
      });
    }
  });
});

// ============================================
// 🔄 UPDATE ADMIN PASSWORD API
// ============================================
exports.updateAdminPassword = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({
          success: false,
          error: "Method not allowed. Use POST.",
        });
      }

      const {email, oldPassword, newPassword} = req.body;

      if (!email || !oldPassword || !newPassword) {
        return res.status(400).json({
          success: false,
          error: "Email, old password, and new password are required",
        });
      }

      const adminsRef = db.collection("admins");

      const adminQuery = await adminsRef.where("email", "==", email).get();

      if (adminQuery.empty) {
        return res.status(404).json({
          success: false,
          error: "Admin not found",
        });
      }

      const adminDoc = adminQuery.docs[0];
      const adminData = adminDoc.data();

      const isOldPasswordValid = await bcrypt.compare(
          oldPassword,
          adminData.password,
      );

      if (!isOldPasswordValid) {
        return res.status(401).json({
          success: false,
          error: "Old password is incorrect",
        });
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);

      await adminsRef.doc(adminDoc.id).update({
        password: hashedNewPassword,
        passwordUpdatedAt:
          admin.firestore.FieldValue.serverTimestamp(),
      });

      return res.status(200).json({
        success: true,
        message: "Password updated successfully",
      });
    } catch (error) {
      console.error("Update password error:", error);

      return res.status(500).json({
        success: false,
        error: "Internal server error",
      });
    }
  });
});
