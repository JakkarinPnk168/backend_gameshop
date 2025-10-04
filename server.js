import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import admin from "firebase-admin";
import bcrypt from "bcrypt";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import dotenv from "dotenv";

dotenv.config(); // โหลดตัวแปรจาก .env

const app = express();
const PORT = process.env.PORT || 3000;

// ==================
// 🔒 1. Firebase Setup (ปลอดภัย)
// ==================
if (!process.env.FIREBASE_KEY) {
  console.error("❌ Missing FIREBASE_KEY environment variable");
  process.exit(1);
}

const serviceAccount = JSON.parse(process.env.FIREBASE_KEY);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// ==================
// 🔒 2. Cloudinary Setup
// ==================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({ storage: multer.memoryStorage() });

// ==================
// 🔧 3. Middleware
// ==================
app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

// ==================
// 🟢 4. Routes
// ==================
app.get("/", (req, res) => {
  res.send("🚀 GameShop Backend is running securely!");
});

// 🔹 Register
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, profileImage } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const snapshot = await db.collection("users").where("email", "==", email).get();
    if (!snapshot.empty) {
      return res.status(400).json({ success: false, message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const userData = {
      name,
      email,
      password: hashedPassword,
      role: "user",
      wallet: 0,
      profileImage: profileImage || "",
      createdAt: new Date()
    };

    const docRef = await db.collection("users").add(userData);

    res.status(201).json({
      success: true,
      userId: docRef.id,
      name: userData.name,
      role: userData.role,
      wallet: userData.wallet,
      profileImage: userData.profileImage,
      message: "Register success"
    });
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

// 🔹 Login
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;

    let userDoc;
    let snapshot = await db.collection("users").where("email", "==", identifier).get();

    if (!snapshot.empty) {
      userDoc = snapshot.docs[0];
    } else {
      snapshot = await db.collection("users").where("name", "==", identifier).get();
      if (!snapshot.empty) {
        userDoc = snapshot.docs[0];
      }
    }

    if (!userDoc) return res.status(400).json({ success: false, message: "ไม่พบผู้ใช้" });

    const user = userDoc.data();
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: "รหัสผ่านไม่ถูกต้อง" });

    res.json({
      success: true,
      userId: userDoc.id,
      name: user.name,
      email: user.email || "",
      role: user.role,
      wallet: user.wallet,
      profileImage: user.profileImage || ""
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

// 🔹 Update User
app.put("/api/users/:id", upload.single("image"), async (req, res) => {
  try {
    const userId = req.params.id;
    const { name, email } = req.body;

    if (!name || !email) {
      return res.status(400).json({ success: false, message: "กรอกข้อมูลให้ครบ" });
    }

    const userRef = db.collection("users").doc(userId);
    const doc = await userRef.get();
    if (!doc.exists) {
      return res.status(404).json({ success: false, message: "ไม่พบผู้ใช้" });
    }
    const oldData = doc.data();

    const snapshot = await db.collection("users").where("email", "==", email).get();
    if (!snapshot.empty && snapshot.docs[0].id !== userId) {
      return res.status(400).json({ success: false, message: "อีเมลนี้ถูกใช้งานแล้ว" });
    }

    let profileImageUrl = oldData.profileImage || "";

    if (req.file) {
      const uploadResult = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: "gameshop_users" },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        stream.end(req.file.buffer);
      });

      profileImageUrl = uploadResult.secure_url;
    }

    const updateData = {
      name,
      email,
      profileImage: profileImageUrl,
      updatedAt: new Date()
    };

    await userRef.update(updateData);

    res.json({
      success: true,
      message: "อัปเดตข้อมูลเรียบร้อย",
      user: {
        userId,
        name,
        email,
        role: oldData.role,
        wallet: oldData.wallet || 0,
        profileImage: profileImageUrl
      }
    });
  } catch (error) {
    console.error("Update User Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

// ==================
// 🚀 Start Server
// ==================
app.listen(PORT, () => {
  console.log(`✅ Server running securely on port ${PORT}`);
});
