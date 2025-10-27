import express from "express";
import cors from "cors";
import admin from "firebase-admin";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import dotenv from "dotenv";
import bcrypt from "bcrypt"; 
import jwt from "jsonwebtoken";
import { FieldValue } from 'firebase-admin/firestore';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;


if (!process.env.FIREBASE_KEY) {
  console.error("❌ Missing FIREBASE_KEY environment variable");
  process.exit(1);
}

const serviceAccount = JSON.parse(process.env.FIREBASE_KEY);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

app.listen(PORT, () => {
  console.log(`✅ Server running securely on port ${PORT}`);
});



cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({ storage: multer.memoryStorage() });


app.use(cors());
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user; // เก็บข้อมูล user ที่ decode แล้วไว้ใน request
    next();
  });
};

// 👮 Middleware สำหรับตรวจสอบว่าเป็น Admin หรือไม่
const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: "Access denied. Admins only." });
    }
    next();
};

// ---------------------------
// ✅ Cache Setup (In-memory)
// ---------------------------
const cache = new Map();
function setCache(key, data, ttl = 30_000) {
  cache.set(key, { data, expire: Date.now() + ttl });
}
function getCache(key) {
  const c = cache.get(key);
  if (!c) return null;
  if (Date.now() > c.expire) {
    cache.delete(key);
    return null;
  }
  return c.data;
}
function clearCacheByPrefix(prefix) {
  for (const key of cache.keys()) {
    if (key.startsWith(prefix)) {
      cache.delete(key);
      console.log(`🧹 Cleared cache key: ${key}`);
    }
  }
}

app.get("/", (req, res) => {
  res.send("🚀 GameShop Backend is running securely!");
});


/////////////////////////// (Register / Login / Update Profile)
// ✅ Register
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, profileImage } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, message: "Missing fields" });

    const cacheKey = `user:${email}`;
    const cached = getCache(cacheKey);
    if (cached) return res.status(400).json({ success: false, message: "Email already registered" });

    const snapshot = await db.collection("users").where("email", "==", email).get();
    if (!snapshot.empty) {
      setCache(cacheKey, true, 60000);
      return res.status(400).json({ success: false, message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      name,
      email,
      password: hashedPassword,
      role: "user",
      wallet: 0,
      profileImage: profileImage || "",
      createdAt: new Date(),
    };

    const docRef = await db.collection("users").add(newUser);
    setCache(`userId:${docRef.id}`, newUser, 60000);

    res.status(201).json({
      success: true,
      userId: docRef.id,
      name,
      role: "user",
      wallet: 0,
      profileImage: newUser.profileImage,
      message: "Register success",
    });
  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

// ✅ Login
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password)
      return res.status(400).json({ success: false, message: "Missing identifier or password" });

    console.log("🔐 Login attempt:", identifier);
    const cacheKey = `login:${identifier}`;

    // ✅ ตรวจ cache ก่อน (ลด Firestore read)
    const cachedUser = getCache(cacheKey);
    if (cachedUser) {
      console.log("⚡ ใช้ข้อมูลจาก cache");
      const match = await bcrypt.compare(password, cachedUser.password);
      if (match) {
        const token = jwt.sign(
          { userId: cachedUser.id, role: cachedUser.publicData.role || "user" },
          process.env.JWT_SECRET || "default_secret",
          { expiresIn: "7d" }
        );

        return res.json({
          success: true,
          userId: cachedUser.id,
          ...cachedUser.publicData,
          token,
        });
      }
    }

    // ✅ ดึง user จาก Firestore
    let snapshot = await db.collection("users").where("email", "==", identifier).get();
    if (snapshot.empty)
      snapshot = await db.collection("users").where("name", "==", identifier).get();

    if (snapshot.empty)
      return res.status(400).json({ success: false, message: "ไม่พบผู้ใช้" });

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    if (!user.password) {
      console.error("⚠️ ผู้ใช้ไม่มีรหัสผ่านในฐานข้อมูล");
      return res.status(400).json({ success: false, message: "บัญชีนี้ไม่มีรหัสผ่าน กรุณาสมัครใหม่" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ success: false, message: "รหัสผ่านไม่ถูกต้อง" });

    const publicData = {
      name: user.name,
      email: user.email || "",
      role: user.role || "user",
      wallet: user.wallet || 0,
      profileImage: user.profileImage || "",
    };

    // ✅ JWT token
    const token = jwt.sign(
      { userId: userDoc.id, role: publicData.role },
      process.env.JWT_SECRET || "default_secret",
      { expiresIn: "7d" }
    );

    // ✅ Cache
    setCache(cacheKey, { id: userDoc.id, password: user.password, publicData }, 60_000);

    console.log("✅ Login success:", user.name, "| Role:", publicData.role);
    res.json({ success: true, userId: userDoc.id, ...publicData, token });

  } catch (error) {
    console.error("❌ Login Error:", error.message);
    res.status(500).json({ success: false, message: "Server Error: " + error.message });
  }
});


// ✅ Update User
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

    // ตรวจอีเมลซ้ำ
    const snapshot = await db.collection("users").where("email", "==", email).get();
    if (!snapshot.empty && snapshot.docs[0].id !== userId) {
      return res.status(400).json({ success: false, message: "อีเมลนี้ถูกใช้งานแล้ว" });
    }

    // จัดการรูปโปรไฟล์ใหม่ (ถ้ามี)
    let profileImageUrl = oldData.profileImage || "";
    if (req.file) {
      const uploadResult = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: "gameshop_users" },
          (error, result) => (error ? reject(error) : resolve(result))
        );
        stream.end(req.file.buffer);
      });
      profileImageUrl = uploadResult.secure_url;
    }

    const updateData = {
      name,
      email,
      profileImage: profileImageUrl,
      updatedAt: new Date(),
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
        profileImage: profileImageUrl,
      },
    });
  } catch (error) {
    console.error("Update User Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});


//////////////////////////////////////////////Admin (oat)

//// ดึงประเภทเกม (คีย์เองที่ไฟล์ seed-categories)
app.get("/api/categories", async (req, res) => {
  const key = "categories";
  const cached = getCache(key);
  if (cached) return res.json({ success: true, categories: cached }); // ✅ wrap ให้เหมือนกันทุกกรณี

  try {
    const snap = await db.collection("categories").get();
    const data = snap.docs.map((d) => ({ id: d.id, ...d.data() }));

    setCache(key, data, 60_000);
    res.json({ success: true, categories: data }); // ✅ เปลี่ยนเป็น object เดียวกับฝั่ง Angular
  } catch (e) {
    console.error("Error loading categories:", e);
    res.status(500).json({ success: false, message: "error loading categories" }); // ✅ เพิ่ม success:false เพื่อความสม่ำเสมอ
  }
});



//// เพิ่มเกม 
app.post("/api/games", upload.single("image"), async (req, res) => {
  try {
    const { name, price, categoryId, description } = req.body;
    if (!name || !price || !categoryId) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }
    if (!req.file) {
      return res.status(400).json({ success: false, message: "Image required" });
    }

    console.log("🟦 เริ่มเพิ่มเกมใหม่:", name);

    // ✅ Upload ไปยัง Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: "gameshop/games" },
        (error, result) => (error ? reject(error) : resolve(result))
      );
      stream.end(req.file.buffer);
    });

    console.log("✅ อัปโหลดภาพสำเร็จ:", uploadResult.secure_url);

    // ✅ ใช้วันที่ปัจจุบันของเซิร์ฟเวอร์
    const releasedAt = new Date();

    const doc = {
      name,
      price: Number(price),
      categoryId,
      description: description || "",
      imageUrl: uploadResult.secure_url,
      imagePublicId: uploadResult.public_id,
      releasedAt,
      totalSold: 0,
      isActive: true,
    };

    console.log("🟩 เพิ่มข้อมูลเกมลง Firestore...");
    const ref = await db.collection("games").add(doc);

    console.log(`🎮 เพิ่มเกมสำเร็จ: ${name} (ID: ${ref.id})`);

    // ✅ เคลียร์ cache ของ /api/games ทั้งหมด
    clearCacheByPrefix("games:");

    // ✅ ส่งข้อมูลกลับ
    return res.status(201).json({
      success: true,
      message: "Game created successfully",
      game: { id: ref.id, ...doc },
    });

  } catch (e) {
    console.error("❌ Error creating game:", e);
    return res.status(500).json({ success: false, message: "Error creating game" });
  }
});



////ดึงรายการเกม
app.get("/api/games", async (req, res) => {
  try {
    const { limit = 12, categoryId, search = "" } = req.query;
    const key = `games:${categoryId || "all"}:${search.toLowerCase()}`;
    const cached = getCache(key);

    // ✅ ถ้ามี cache ให้ส่งกลับทันที
    if (cached) {
      return res.json({ success: true, games: cached.slice(0, Number(limit)) });
    }

    const snap = await db.collection("games").get();

    let games = snap.docs
      .map((d) => {
        const data = d.data();
        let releasedAt = null;

        // ✅ รองรับ Timestamp, Date, String
        if (data.releasedAt) {
          if (typeof data.releasedAt === "object" && "seconds" in data.releasedAt) {
            releasedAt = new Date(data.releasedAt.seconds * 1000);
          } else if (data.releasedAt instanceof Date) {
            releasedAt = data.releasedAt;
          } else if (typeof data.releasedAt === "string") {
            const parsed = new Date(data.releasedAt);
            releasedAt = isNaN(parsed.getTime()) ? null : parsed;
          }
        }

        return {
          id: d.id,
          ...data,
          releasedAt,
        };
      })
      .filter((g) => g.isActive !== false);

    // ✅ ถ้ามี category ให้กรอง
    if (categoryId) {
      games = games.filter((g) => g.categoryId === categoryId);
    }

    // ✅ เพิ่มระบบค้นหาชื่อเกม (case-insensitive + partial match)
    if (search && search.trim() !== "") {
      const term = search.toLowerCase();
      games = games.filter((g) =>
        g.name?.toLowerCase().includes(term)
      );
    }

    // ✅ เรียงจากเกมใหม่สุด -> เก่าสุด
    games.sort((a, b) => {
      const aTime = a.releasedAt ? new Date(a.releasedAt).getTime() : 0;
      const bTime = b.releasedAt ? new Date(b.releasedAt).getTime() : 0;
      return bTime - aTime;
    });

    // ✅ เก็บ cache 30 วินาที
    setCache(key, games, 30_000);

    // ✅ ส่งกลับ
    res.json({ success: true, games: games.slice(0, Number(limit)) });
  } catch (e) {
    console.error("❌ Error loading games:", e);
    res.status(500).json({ success: false, message: "Error loading games" });
  }
});




//// ดึงรายละเอียดเกม
app.get("/api/games/:id", async (req, res) => {
  try {
    const gameId = req.params.id;
    console.log("📡 [GET] /api/games/:id | id =", gameId);

    const doc = await db.collection("games").doc(gameId).get();
    if (!doc.exists) {
      console.warn("⚠️ Game not found:", gameId);
      return res.status(404).json({ success: false, message: "Game not found" });
    }

    const data = doc.data() || {};
    let releasedAt = null;

    // ✅ ป้องกัน undefined และแปลงวันที่ให้เป็น Date เสมอ
    if (data.releasedAt) {
      if (typeof data.releasedAt === "object" && "seconds" in data.releasedAt) {
        releasedAt = new Date(data.releasedAt.seconds * 1000);
      } else if (typeof data.releasedAt === "string" || typeof data.releasedAt === "number") {
        const parsed = new Date(data.releasedAt);
        releasedAt = isNaN(parsed.getTime()) ? null : parsed;
      }
    }

    // ✅ ดึงชื่อประเภทเกม (categoryName)
    let categoryName = "ไม่ทราบประเภท";
    if (data.categoryId) {
      const catDoc = await db.collection("categories").doc(data.categoryId).get();
      if (catDoc.exists) {
        const catData = catDoc.data();
        categoryName = catData?.name || categoryName;
      }
    }

    // ✅ คำนวณอันดับเกมตามยอดขาย (totalSold)
    const allGamesSnap = await db.collection("games").get();
    const sortedGames = allGamesSnap.docs
      .map((d) => ({
        id: d.id,
        totalSold: d.data()?.totalSold || 0
      }))
      .sort((a, b) => b.totalSold - a.totalSold);

    const rank = sortedGames.findIndex((g) => g.id === gameId) + 1;

    // ✅ รวมข้อมูลเกมทั้งหมด
    const game = {
      id: doc.id,
      ...data,
      releasedAt,
      categoryName,
      rank,
    };

    console.log(
      `🎮 ส่งข้อมูลเกม: ${game.name || "(no name)"} | Rank: ${rank} | Category: ${categoryName}`
    );

    return res.json({ success: true, game });
  } catch (error) {
    console.error("❌ Error fetching game by ID:", error);
    return res.status(500).json({ success: false, message: "Error fetching game" });
  }
});





//// อัปเดตเกม
app.put("/api/games/:id", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    const { name, price, categoryId, description } = req.body;
    const gameRef = db.collection("games").doc(req.params.id);
    const oldDoc = await gameRef.get();

    if (!oldDoc.exists) {
      return res.status(404).json({ success: false, message: "ไม่พบข้อมูลเกม" });
    }

    const patch = {
      name: name?.trim() || oldDoc.data().name,
      price: Number(price) || oldDoc.data().price,
      categoryId: categoryId || oldDoc.data().categoryId,
      description: description || oldDoc.data().description,
      updatedAt: new Date(),
    };

    // ✅ ถ้ามีรูปใหม่ → ลบของเก่าและอัปโหลดใหม่
    if (req.file) {
      const oldData = oldDoc.data();
      if (oldData.imagePublicId) {
        try {
          await cloudinary.uploader.destroy(oldData.imagePublicId);
          console.log(`🗑️ ลบภาพเก่าจาก Cloudinary สำเร็จ: ${oldData.imagePublicId}`);
        } catch (err) {
          console.warn("⚠️ ลบภาพเก่าไม่สำเร็จ:", err.message);
        }
      }

      const uploadResult = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: "gameshop/games" },
          (error, result) => (error ? reject(error) : resolve(result))
        );
        stream.end(req.file.buffer);
      });

      patch.imageUrl = uploadResult.secure_url;
      patch.imagePublicId = uploadResult.public_id;
    }

    await gameRef.update(patch);
    const updatedDoc = await gameRef.get();

    // ✅ ล้าง cache ทันทีหลังแก้ไข
    clearCacheByPrefix("games:");

    res.json({
      success: true,
      message: "อัปเดตเกมสำเร็จ",
      game: { id: updatedDoc.id, ...updatedDoc.data() },
    });
  } catch (e) {
    console.error("❌ Error updating game:", e);
    res.status(500).json({ success: false, message: "Error updating game" });
  }
});



//// ลบเกม
app.delete("/api/games/:id", authenticateToken, async (req, res) => {
  try {
    const ref = db.collection("games").doc(req.params.id);
    const doc = await ref.get();

    if (!doc.exists) {
      return res.status(404).json({ success: false, message: "ไม่พบข้อมูลเกม" });
    }

    const data = doc.data();

    // ✅ ลบรูปออกจาก Cloudinary
    if (data.imagePublicId) {
      try {
        await cloudinary.uploader.destroy(data.imagePublicId);
        console.log(`🗑️ ลบภาพจาก Cloudinary สำเร็จ: ${data.imagePublicId}`);
      } catch (err) {
        console.warn("⚠️ ลบภาพจาก Cloudinary ไม่สำเร็จ:", err.message);
      }
    }

    // ✅ ลบจาก Firestore
    await ref.delete();
    console.log(`🔥 ลบเกมออกจาก Firestore แล้ว: ${req.params.id}`);

    // ✅ ล้าง cache หลังลบ
    clearCacheByPrefix("games:");

    res.json({ success: true, message: "ลบเกมสำเร็จ", deletedId: req.params.id });
  } catch (e) {
    console.error("❌ Error deleting game:", e);
    res.status(500).json({ success: false, message: "Error deleting game" });
  }
});


app.get("/api/games/top/list", async (req, res) => {
  try {
    const { limit = 5, date } = req.query;

    if (date && isNaN(Date.parse(date))) {
      console.warn("⚠️ Invalid date format:", date);
      return res.status(400).json({ message: "รูปแบบวันที่ไม่ถูกต้อง (yyyy-mm-dd)" });
    }

    if (date) {
      const start = admin.firestore.Timestamp.fromDate(new Date(`${date}T00:00:00+07:00`));
      const end = admin.firestore.Timestamp.fromDate(new Date(`${date}T23:59:59+07:00`));

      console.log(`📅 ดึงยอดขายเฉพาะวันที่: ${date}`);

      const snap = await db
        .collection("orders")
        .where("createdAt", ">=", start)
        .where("createdAt", "<=", end)
        .where("status", "==", "completed")
        .get();


      if (snap.empty) {
        console.log("❌ ไม่มีคำสั่งซื้อในวันนี้");
        return res.json([]);
      }

      const salesMap = {};

      snap.docs.forEach(doc => {
        const data = doc.data();

        if (!data.gameId) return;

        const gameId = data.gameId;
        const qty = Number(data.quantity || 1);
        const gameName = data.gameName || "Unknown";

        if (!salesMap[gameId]) {
          salesMap[gameId] = { totalSold: 0, gameName };
        }
        salesMap[gameId].totalSold += qty;
      });

      if (Object.keys(salesMap).length === 0) {
        console.log("ℹ️ ไม่มียอดขายที่ตรงเงื่อนไขในวันนี้");
        return res.json([]);
      }

      const gameSnap = await db.collection("games").get();
      const games = {};
      gameSnap.docs.forEach(g => (games[g.id] = g.data()));

      const result = Object.entries(salesMap).map(([gameId, info]) => ({
        id: gameId,
        name: info.gameName || games[gameId]?.name || "Unknown",
        totalSold: info.totalSold,
        imageUrl: games[gameId]?.imageUrl || "",
        price: games[gameId]?.price || 0,
        date,
      }));

      result.sort((a, b) => b.totalSold - a.totalSold);

      console.log(`✅ ส่งข้อมูลอันดับขายดี ${result.length} รายการ`);
      return res.json(result.slice(0, Number(limit)));
    }

    const allGamesSnap = await db.collection("games").get();
    let games = allGamesSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    games = games.filter(g => g.isActive !== false);
    games.sort((a, b) => (b.totalSold || 0) - (a.totalSold || 0));

    res.json(games.slice(0, Number(limit)));

  } catch (e) {
    console.error("❌ Error fetching top games:", e);
    res.status(200).json([]); 
  }
});

// ✅ ดึงอันดับขายดีตามวันที่
// app.get("/api/ranking", async (req, res) => {
//   const { start, end } = req.query;
//   const startDate = new Date(start);
//   const endDate = new Date(end);

//   try {
//     const snapshot = await db
//       .collection("orders") // collection ที่เก็บข้อมูลการสั่งซื้อ
//       .where("createdAt", ">=", startDate)
//       .where("createdAt", "<=", endDate)
//       .get();

//     if (snapshot.empty) {
//       return res.json([]); // ไม่มีข้อมูลของวันนั้น
//     }

//     const sales = {};
//     snapshot.forEach((doc) => {
//       const data = doc.data();
//       if (Array.isArray(data.games)) {
//         data.games.forEach((g) => {
//           const name = g.name || 'ไม่ทราบชื่อเกม';
//           sales[name] = (sales[name] || 0) + 1;
//         });
//       }
//     });

//     const sorted = Object.entries(sales)
//       .map(([name, totalSold]) => ({ name, totalSold }))
//       .sort((a, b) => b.totalSold - a.totalSold);

//     res.json(sorted);
//   } catch (err) {
//     console.error('Error loading ranking:', err);
//     res.status(500).json({ message: 'Error loading ranking' });
//   }
// });



//// รวมธุรกรรมผู้ใช้ (ซื้อเกม + เติมเงิน)
app.get("/api/transactions/all", async (req, res) => {
  try {
    const transactions = [];

    const userSnap = await db.collection("users").get();
    const userMap = {};
    userSnap.docs.forEach(doc => {
      const data = doc.data();
      userMap[doc.id] = data.name || "ไม่ระบุชื่อ";
    });

    //// ดึงข้อมูลคำสั่งซื้อเกม (orders)
    const orderSnap = await db
      .collection("orders")
      .where("status", "==", "completed")
      .get();

    orderSnap.docs.forEach(doc => {
      const d = doc.data();
      transactions.push({
        userId: d.userId || "unknown",
        userName: userMap[d.userId] || "ไม่ระบุชื่อ",
        type: "ซื้อเกม",
        amount: d.price || 0,
        createdAt: d.createdAt?.toDate() || new Date(),
      });
    });

    //// ดึงข้อมูลการเติมเงินจาก topup_history
    const topupSnap = await db
      .collection("topup_history")
      .where("status", "==", "completed")
      .get();

    topupSnap.docs.forEach(doc => {
      const d = doc.data();
      transactions.push({
        userId: d.userId || "unknown",
        userName: userMap[d.userId] || "ไม่ระบุชื่อ",
        type: "เติมเงิน",
        amount: d.amount || 0,
        createdAt: d.createdAt?.toDate() || new Date(),
      });
    });

    transactions.sort((a, b) => b.createdAt - a.createdAt);

    console.log("✅ รวมธุรกรรมทั้งหมด:", transactions.length);
    res.json(transactions);
  } catch (e) {
    console.error("❌ Error fetching transactions:", e);
    res.status(500).json({ message: "Error fetching transactions" });
  }
});



////////////////////////////////โค้ดส่วนลด 
////////// Admin


//// ดึงรายการโค้ดส่วนลด (Admin)
app.get("/api/discounts", async (req, res) => {
  try {
    const now = new Date();
    const snap = await db.collection("discounts").orderBy("createdAt", "desc").get();

    const updates = []; // เก็บรายการที่ต้องอัปเดตสถานะหมดอายุ

    const discounts = snap.docs.map((doc) => {
      const data = doc.data();

      // ✅ ตรวจสอบวันหมดอายุ
      let expireDate = null;
      if (data.expireAt?.toDate) {
        expireDate = data.expireAt.toDate();
      } else if (typeof data.expireAt === "string") {
        expireDate = new Date(data.expireAt);
      }

      // ถ้าโค้ดหมดอายุและยังไม่ถูกปิด → ปิดให้อัตโนมัติ
      if (expireDate && expireDate < now && data.isActive) {
        updates.push(doc.ref.update({ isActive: false, updatedAt: now }));
        data.isActive = false;
      }

      const status =
        !data.isActive
          ? "ถูกปิดใช้งาน"
          : data.usedCount >= data.usageLimit
          ? "ถูกใช้ครบแล้ว"
          : "ใช้งานได้";

      return { id: doc.id, ...data, status };
    });

    // ✅ อัปเดต Firestore สำหรับโค้ดที่หมดอายุจริง ๆ
    if (updates.length > 0) {
      await Promise.all(updates);
      console.log(`🕒 ปิดโค้ดหมดอายุแล้ว ${updates.length} รายการ`);
    }

    res.json(discounts);
  } catch (error) {
    console.error("❌ Error fetching discounts:", error);
    res.status(500).json({ message: "Error fetching discounts" });
  }
});


// ✅ เพิ่มโค้ดส่วนลด (Admin)
app.post("/api/discounts", async (req, res) => {
  try {
    const { code, type, value, minSpend, maxDiscount, expireAt, usageLimit } = req.body;

    if (!code || !type || !value || !expireAt)
      return res.status(400).json({ message: "กรุณากรอกข้อมูลให้ครบ" });

    // ป้องกันโค้ดซ้ำ
    const exist = await db.collection("discounts").where("code", "==", code.toUpperCase()).get();
    if (!exist.empty) return res.status(400).json({ message: "โค้ดนี้มีอยู่แล้ว" });

    const newDiscount = {
      code: code.toUpperCase(),
      type,
      value: Number(value),
      minSpend: Number(minSpend) || 0,
      maxDiscount: Number(maxDiscount) || null,
      expireAt: new Date(expireAt),
      isActive: true,
      usedBy: [],
      usedCount: 0,
      usageLimit: Number(usageLimit) || 1,
      createdAt: new Date(),
    };

    await db.collection("discounts").add(newDiscount);
    res.json({ success: true, message: "เพิ่มโค้ดส่วนลดเรียบร้อย" });
  } catch (error) {
    console.error("❌ Error creating discount:", error);
    res.status(500).json({ message: "Error creating discount" });
  }
});

app.put("/api/discounts/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { type, value, minSpend, maxDiscount, expireAt, usageLimit, isActive } = req.body;

    const ref = db.collection("discounts").doc(id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ message: "ไม่พบโค้ดนี้" });

    const updateData = {
      type,
      value: Number(value),
      minSpend: Number(minSpend) || 0,
      maxDiscount: Number(maxDiscount) || null,
      expireAt: expireAt ? new Date(expireAt) : doc.data().expireAt,
      usageLimit: Number(usageLimit) || doc.data().usageLimit,
      isActive: typeof isActive === "boolean" ? isActive : doc.data().isActive,
      updatedAt: new Date(),
    };

    await ref.update(updateData);
    res.json({ success: true, message: "อัปเดตโค้ดส่วนลดสำเร็จ" });
  } catch (error) {
    console.error("❌ Error updating discount:", error);
    res.status(500).json({ message: "Error updating discount" });
  }
});

//// ตรวจสอบโค้ดก่อนใช้ (User ใช้ในตะกร้า)
app.get("/api/discounts/check/:code", async (req, res) => {
  try {
    const code = req.params.code.trim().toUpperCase();
    const { userId, total } = req.query;

    const snap = await db.collection("discounts").where("code", "==", code).limit(1).get();
    if (snap.empty) return res.status(404).json({ message: "ไม่พบโค้ดส่วนลดนี้" });

    const discountDoc = snap.docs[0];
    const data = discountDoc.data();
    const now = new Date();

    if (!data.isActive) return res.status(400).json({ message: "โค้ดนี้ไม่สามารถใช้งานได้" });
    if (data.usedCount >= data.usageLimit)
      return res.status(400).json({ message: "โค้ดนี้ถูกใช้ครบแล้ว" });
    if (data.expireAt.toDate() < now)
      return res.status(400).json({ message: "โค้ดหมดอายุแล้ว" });
    if (data.minSpend && total && Number(total) < data.minSpend)
      return res.status(400).json({ message: `ยอดขั้นต่ำต้องมากกว่า ${data.minSpend} บาท` });
    if (data.usedBy?.includes(userId))
      return res.status(400).json({ message: "คุณใช้โค้ดนี้ไปแล้ว" });

    res.json({
      success: true,
      discount: { id: discountDoc.id, ...data },
      message: "โค้ดสามารถใช้งานได้",
    });
  } catch (error) {
    console.error("❌ Error checking discount:", error);
    res.status(500).json({ message: "Error checking discount" });
  }
});

// ✅ ใช้โค้ดส่วนลด (User กดใช้ในตะกร้า)
// app.post("/api/discounts/use", async (req, res) => {
//   try {
//     const { userId, code } = req.body;

//     const snap = await db.collection("discounts")
//       .where("code", "==", code.toUpperCase())
//       .limit(1)
//       .get();

//     if (snap.empty)
//       return res.status(404).json({ message: "ไม่พบโค้ดส่วนลด" });

//     const ref = snap.docs[0].ref;
//     const data = snap.docs[0].data();
//     const now = new Date();

//     // ✅ ตรวจสอบสถานะและการใช้
//     if (!data.isActive)
//       return res.status(400).json({ message: "โค้ดนี้ไม่สามารถใช้งานได้" });
//     if (data.expireAt.toDate() < now)
//       return res.status(400).json({ message: "โค้ดหมดอายุแล้ว" });
//     if (data.usedBy?.includes(userId))
//       return res.status(400).json({ message: "คุณใช้โค้ดนี้ไปแล้ว" });

//     const newUsedCount = (data.usedCount || 0) + 1;
//     const stillActive = newUsedCount < (data.usageLimit || 1);

//     // ✅ อัปเดตสถานะ
//     await ref.update({
//       usedBy: admin.firestore.FieldValue.arrayUnion(userId),
//       usedCount: newUsedCount,
//       isActive: stillActive,
//     });

//     // ✅ หากใช้ครบ → ปิดการใช้งาน
//     if (!stillActive) {
//       console.log(`⚙️ ปิดโค้ด ${data.code} แล้ว (ครบ ${newUsedCount}/${data.usageLimit})`);
//     }

//     res.json({
//       success: true,
//       message: stillActive
//         ? "ใช้โค้ดส่วนลดสำเร็จ"
//         : "ใช้โค้ดส่วนลดสำเร็จ และโค้ดนี้ถูกปิดการใช้งานแล้ว",
//     });
//   } catch (error) {
//     console.error("❌ Error using discount:", error);
//     res.status(500).json({ message: "Error using discount" });
//   }
// });

//  ลบโค้ด
app.delete("/api/discounts/:id", async (req, res) => {
  try {
    await db.collection("discounts").doc(req.params.id).delete();
    res.json({ success: true, message: "ลบโค้ดส่วนลดเรียบร้อย" });
  } catch (error) {
    console.error("❌ Error deleting discount:", error);
    res.status(500).json({ message: "Error deleting discount" });
  }
});

//  Toggle active status
app.put("/api/discounts/:id/toggle", async (req, res) => {
  try {
    const { id } = req.params;
    const { isActive } = req.body;
    if (typeof isActive !== "boolean")
      return res.status(400).json({ success: false, message: "Missing isActive boolean" });

    await db.collection("discounts").doc(id).update({ isActive });
    res.json({ success: true, message: "อัปเดตสถานะโค้ดสำเร็จ" });
  } catch (error) {
    console.error("toggle error:", error);
    res.status(500).json({ success: false, message: "Server error while toggling discount" });
  }
});





///////////////////////////user (oat)

//  ระบบคำสั่งซื้อ (Orders)
//  บันทึกออเดอร์และอัปเดตส่วนลด
app.post("/api/orders", async (req, res) => {
  const { userId, gameId, gameName, price, quantity, redeemCode } = req.body;

  try {
    // 1️⃣ สร้างข้อมูลออเดอร์
    const orderData = {
      userId,
      gameId,
      gameName,
      price,
      quantity,
      redeemCode: redeemCode || null,
      status: "completed",
      createdAt: new Date()
    };

    await db.collection("orders").add(orderData);
    console.log("✅ Order created:", orderData);

   
    if (redeemCode) {
      console.log("🔍 Checking discount code:", redeemCode);

      const discountRef = db.collection("discounts").where("code", "==", redeemCode);
      const snapshot = await discountRef.get();

      if (snapshot.empty) {
        console.warn(`⚠️ Discount code ${redeemCode} not found`);
      } else {
        const doc = snapshot.docs[0];
        const data = doc.data();


        const newCount = (data.usedCount || 0) + 1;

        await doc.ref.update({
          usedCount: newCount,
          lastUsedAt: new Date()
        });

        console.log(`✅ Updated ${redeemCode} usedCount = ${newCount}`);
      }
    }

    res.json({ success: true, message: "Order created successfully" });
  } catch (error) {
    console.error("❌ Error saving order:", error);
    res.status(500).json({ success: false, message: "Error saving order" });
  }
});













//////////////////////////////////////////////User (Tee)

//=================< ประวัติคำสั่งซื้อของผู้ใช้ >=======================//
app.get("/api/orders/my-history", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { limit = 10 } = req.query;

    const snapshot = await db.collection('orders')
      .where('userId', '==', userId)
      .orderBy('createdAt', 'desc')
      .limit(Number(limit))
      .select('gameName', 'price', 'status', 'createdAt', 'quantity', 'redeemCode') 
      .get();

    const orders = snapshot.docs.map(doc => {
      const data = doc.data();
      return {
        id: doc.id,
        gameName: data.gameName,
        price: data.price,
        status: data.status,
        quantity: data.quantity || 1,
        redeemCode: data.redeemCode || '',
        createdAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : null
      };
    });

    res.json({ success: true, orders });
  } catch (error) {
    console.error("Error fetching order history:", error);
    res.status(500).json({ success: false, message: "Error fetching history" });
  }
});

//=====================< รายการเกมที่ผู้ใช้คนหนึ่งเคยซื้อ (Library ของผู้ใช้) >=======================//
app.get("/api/users/my-games", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const librarySnapshot = await db.collection(`users/${userId}/library`)
      .select('addedAt')
      .get();
    if (librarySnapshot.empty) return res.json({ success: true, games: [] });

    const gameIds = librarySnapshot.docs.map(doc => doc.id);
    const BATCH_SIZE = 10;
    const ownedGames = [];

    for (let i = 0; i < gameIds.length; i += BATCH_SIZE) {
      const batchIds = gameIds.slice(i, i + BATCH_SIZE);
      const batchSnap = await db.collection('games')
        .where(admin.firestore.FieldPath.documentId(), 'in', batchIds)
        .select('name', 'price', 'imageUrl')
        .get();
      ownedGames.push(...batchSnap.docs.map(doc => ({ id: doc.id, ...doc.data() })));
    }

    res.json({ success: true, games: ownedGames });
  } catch (error) {
    console.error("Error fetching user's games:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

//=====================< เติมเงินเข้ากระเป๋าผู้ใช้ >=======================//
app.post("/api/users/topup", authenticateToken, async (req, res) => {
  try {
    const { amount, method } = req.body;
    const userId = req.user.userId;
    if (!amount || amount <= 0) return res.status(400).json({ success: false, message: "Invalid amount" });

    const userRef = db.collection('users').doc(userId);

    await db.runTransaction(async (t) => {
      t.update(userRef, { wallet: FieldValue.increment(amount) });
      t.set(db.collection('topup_history').doc(), {
        userId,
        amount,
        method: method || 'wallet',
        createdAt: FieldValue.serverTimestamp()
      });
    });

    const updated = await userRef.get();
    res.json({ success: true, newWallet: updated.data().wallet });
  } catch (e) {
    console.error("Top-up Error:", e);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

//=====================< ประวัติการเติมเงินของผู้ใช้ >=======================//
app.get("/api/topup-history", authenticateToken, async (req, res) => {
  try {
    console.log("🟢 Token verified. req.user =", req.user);

    const userId = req.user.userId; // เช็คตรงนี้ด้วย
    console.log("📌 userId from token:", userId);

    if (!userId) {
      console.warn("⚠️ No userId found in token payload");
      return res.status(403).json({ success: false, message: "Invalid token data" });
    }

    const snapshot = await db.collection('topup_history')
      .where('userId', '==', userId)
      .orderBy('createdAt', 'desc')
      .limit(5)
      .select('amount', 'method', 'createdAt')
      .get();

    const history = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      createdAt: doc.data().createdAt?.toDate ? doc.data().createdAt.toDate() : null
    }));

    res.json({ success: true, history });
  } catch (err) {
    console.error("❌ Error fetching history:", err);
    res.status(500).json({ success: false, message: "Error fetching history" });
  }
});


// ✅ ดึงรายละเอียดเกม
// app.get("/api/games/:id", async (req, res) => {
//   try {
//     const doc = await db.collection("games").doc(req.params.id).get();
//     if (!doc.exists) return res.status(404).json({ message: "Game not found" });

//     const gameData = { id: doc.id, ...doc.data() };

//     // ================== แปลง Timestamp เป็น Date ==================
//     if (gameData.releasedAt && typeof gameData.releasedAt === 'object') {
//       const seconds = gameData.releasedAt._seconds || gameData.releasedAt.seconds;
//       if (seconds) gameData.releasedAt = new Date(seconds * 1000);
//     }

//     // ================== จัดอันดับ ==================
//     const allGamesSnap = await db.collection("games").get();
//     const allGames = allGamesSnap.docs.map(d => ({ id: d.id, ...d.data() }));
//     allGames.sort((a, b) => (b.totalSold || 0) - (a.totalSold || 0));
//     const rank = allGames.findIndex(g => g.id === doc.id) + 1;

//     // ================== ดึงชื่อ category ==================
//     let categoryName = null;
//     if (gameData.categoryId) {
//       const categoryDoc = await db.collection("categories").doc(gameData.categoryId).get();
//       if (categoryDoc.exists) {
//         categoryName = categoryDoc.data().name;
//       }
//     }

//     // ================== รวมข้อมูลทั้งหมด ==================
//     const result = {
//       ...gameData,
//       rank,
//       category: categoryName,
//       gameType: gameData.gameType || null
//     };
//     // console.log("🎮 ส่งข้อมูลเกม:", result);
//     res.json(result);

//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: "เกิดข้อผิดพลาดจากเซิร์ฟเวอร์" });
//   }
// });

//=====================< ซื้อเกมแบบทันที >=======================//
app.post("/api/orders/buy", authenticateToken, async (req, res) => {
  try {
    const { gameId } = req.body;
    const userId = req.user.userId;

    if (!gameId) {
      return res.status(400).json({ success: false, message: "Missing gameId" });
    }

    const userRef = db.collection("users").doc(userId);
    const gameRef = db.collection("games").doc(gameId);

    const [userDoc, gameDoc] = await Promise.all([userRef.get(), gameRef.get()]);

    if (!userDoc.exists)
      return res.status(404).json({ success: false, message: "User not found" });
    if (!gameDoc.exists)
      return res.status(404).json({ success: false, message: "Game not found" });

    const user = userDoc.data();
    const game = gameDoc.data();

    if (user.wallet < game.price) {
      return res.status(400).json({ success: false, message: "เงินในกระเป๋าไม่พอ" });
    }

    const orderRef = db.collection("orders").doc();

    await db.runTransaction(async (transaction) => {
      // ✅ หักเงิน
      transaction.update(userRef, { wallet: user.wallet - game.price });

      // ✅ สร้างออเดอร์ใหม่
      transaction.set(orderRef, {
        userId,
        gameId,
        gameName: game.name,
        quantity: 1,
        price: game.price,
        status: "completed",
        redeemCode: "",
        createdAt: FieldValue.serverTimestamp(),
      });

      // ✅ เพิ่มยอดขายเกม
      transaction.update(gameRef, { totalSold: (game.totalSold || 0) + 1 });

      // ✅ เพิ่มเกมเข้า Library
      const libraryRef = db.collection(`users/${userId}/library`).doc(gameId);
      transaction.set(libraryRef, {
        addedAt: FieldValue.serverTimestamp(),
      });
    });

    const updatedUserDoc = await userRef.get();
    const newWallet = updatedUserDoc.data().wallet;

    res.json({
      success: true,
      newWallet,
      order: {
        id: orderRef.id,
        gameName: game.name,
        price: game.price,
        status: "completed",
      },
      message: "ซื้อเกมสำเร็จและเพิ่มในคลังเรียบร้อย ✅",
    });
  } catch (error) {
    console.error("Buy Game Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});



//=====================< รายการสินค้าที่อยู่ในตะกร้าของผู้ใช้ >=======================//
app.get("/api/users/cart", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const snapshot = await db.collection(`users/${userId}/cart`).get();
    const items = snapshot.docs.map(doc => ({ gameId: doc.id, quantity: doc.data().quantity }));
    res.json({ success: true, items });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

//=====================< เพิ่มเกมลงในตะกร้าของผู้ใช้ >=======================//
app.post("/api/users/cart/add", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { gameId, quantity } = req.body;

    const cartRef = db.collection(`users/${userId}/cart`).doc(gameId);
    const cartDoc = await cartRef.get();

    if (cartDoc.exists) {
      await cartRef.update({ quantity: FieldValue.increment(quantity || 1) });
    } else {
      await cartRef.set({ quantity: quantity || 1 });
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

//=====================< ลบเกมในตะกร้าของผู้ใช้ >=======================//
app.post("/api/users/cart/remove", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { gameId } = req.body;
    await db.collection(`users/${userId}/cart`).doc(gameId).delete();
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});

//=====================< ชำระเงินในตะกร้าเกมของผู้ใช้ >=======================//
app.post("/api/users/cart/checkout", authenticateToken, async (req, res) => {
  let discountDocRef = null; // เก็บ ref ของโค้ดส่วนลด
  let discountData = null;   // เก็บข้อมูลของโค้ด
  let promoCodeUsed = false; // ไว้เช็คว่ามีการอัปเดตส่วนลดจริงไหม
  let userIdRolledBack = null; // สำหรับ rollback

  try {
    const userId = req.user.userId;
    const { promoCode } = req.body;

    // 1️⃣ ดึงตะกร้าผู้ใช้
    const cartSnapshot = await db.collection(`users/${userId}/cart`).get();
    if (cartSnapshot.empty)
      return res.status(400).json({ success: false, message: "ตะกร้าว่าง" });

    const cartItems = cartSnapshot.docs.map((doc) => ({
      gameId: doc.id,
      quantity: doc.data().quantity || 1,
    }));

    // 2️⃣ ดึง library ของผู้ใช้ (เฉพาะ id)
    const librarySnapshot = await db
      .collection(`users/${userId}/library`)
      .select()
      .get();
    const ownedGameIds = librarySnapshot.docs.map((doc) => doc.id);

    // ✅ กรองเกมที่ผู้ใช้มีแล้วออก
    const filteredCart = cartItems.filter(
      (item) => !ownedGameIds.includes(item.gameId)
    );
    if (!filteredCart.length)
      return res
        .status(400)
        .json({ success: false, message: "คุณมีเกมทั้งหมดในตะกร้าแล้ว" });

    // 3️⃣ ดึงข้อมูลเกม (batch เพื่อเลี่ยง limit Firestore)
    const BATCH_SIZE = 10;
    let gamesData = [];

    for (let i = 0; i < filteredCart.length; i += BATCH_SIZE) {
      const batchIds = filteredCart.slice(i, i + BATCH_SIZE).map((i) => i.gameId);
      const batchSnap = await db
        .collection("games")
        .where(admin.firestore.FieldPath.documentId(), "in", batchIds)
        .select("name", "price", "totalSold")
        .get();

      gamesData.push(...batchSnap.docs.map((d) => ({ id: d.id, ...d.data() })));
    }

    const gameMap = Object.fromEntries(gamesData.map((g) => [g.id, g]));

    // 4️⃣ คำนวณราคารวม
    let total = filteredCart.reduce((sum, item) => {
      const game = gameMap[item.gameId];
      return sum + (game?.price || 0) * item.quantity;
    }, 0);

    // 5️⃣ ตรวจสอบส่วนลด (discount)
    let discount = 0;

    if (promoCode) {
      const discountSnap = await db
        .collection("discounts")
        .where("code", "==", promoCode.toUpperCase())
        .limit(1)
        .get();

      if (!discountSnap.empty) {
        discountDocRef = discountSnap.docs[0].ref;
        discountData = discountSnap.docs[0].data();

        let expireDate = null;
        if (discountData.expireAt?.toDate) {
          expireDate = discountData.expireAt.toDate();
        } else if (typeof discountData.expireAt === "string") {
          expireDate = new Date(discountData.expireAt);
        }

        const now = new Date();

        if (discountData.isActive && (!expireDate || expireDate > now)) {
          if (discountData.type === "percent") {
            discount = (total * (discountData.value || 0)) / 100;
          } else if (discountData.type === "fixed") {
            discount = discountData.value || 0;
          }
        } else {
          console.warn(`⚠️ โค้ด ${promoCode} หมดอายุหรือไม่ใช้งานแล้ว`);
        }
      }
    }

    const finalTotal = Math.max(total - discount, 0);

    // 6️⃣ ดึงข้อมูลผู้ใช้
    const userRef = db.collection("users").doc(req.user.userId);
    const userDoc = await userRef.get();
    if (!userDoc.exists)
      return res.status(404).json({ success: false, message: "ไม่พบผู้ใช้" });

    const user = userDoc.data();
    if ((user.wallet || 0) < finalTotal)
      return res.status(400).json({ success: false, message: "เงินไม่พอ" });

    // 7️⃣ ทำธุรกรรม Firestore Transaction
    await db.runTransaction(async (transaction) => {
      // หักเงินในกระเป๋า
      transaction.update(userRef, {
        wallet: (user.wallet || 0) - finalTotal,
      });

      for (const item of filteredCart) {
        const game = gameMap[item.gameId];
        if (!game) continue;

        const orderRef = db.collection("orders").doc();
        transaction.set(orderRef, {
          userId,
          gameId: item.gameId,
          gameName: game.name,
          quantity: item.quantity,
          price: game.price * item.quantity,
          status: "completed",
          redeemCode: promoCode || "",
          createdAt: FieldValue.serverTimestamp(),
        });

        // เพิ่มยอดขายของเกม
        const gameRef = db.collection("games").doc(item.gameId);
        transaction.update(gameRef, {
          totalSold: (game.totalSold || 0) + item.quantity,
        });

        // เพิ่มเข้า library
        const libraryRef = db.collection(`users/${userId}/library`).doc(item.gameId);
        transaction.set(libraryRef, {
          addedAt: FieldValue.serverTimestamp(),
        });
      }

      // ✅ ลบตะกร้าหลังชำระเงินเสร็จ
      cartSnapshot.docs.forEach((doc) => transaction.delete(doc.ref));
    });

    // ✅ อัปเดตสถานะโค้ดส่วนลดหลังจาก transaction สำเร็จ
    if (promoCode && discountDocRef && discountData) {
      try {
        const newUsedCount = (discountData.usedCount || 0) + 1;
        const usageLimit = discountData.usageLimit || 1;
        const stillActive = newUsedCount < usageLimit;

        await discountDocRef.update({
          usedBy: admin.firestore.FieldValue.arrayUnion(userId),
          usedCount: newUsedCount,
          lastUsedAt: new Date(),
          isActive: stillActive,
          updatedAt: new Date(),
        });

        promoCodeUsed = true;
        userIdRolledBack = userId;

        console.log(
          `🎟️ โค้ด ${promoCode} ถูกใช้โดย ${userId} (${newUsedCount}/${usageLimit})`
        );

        if (!stillActive) {
          console.log(`⚙️ ปิดโค้ด ${promoCode} แล้ว (ครบจำนวนการใช้งาน)`);
        }
      } catch (discountErr) {
        console.error("❌ Error updating discount usage:", discountErr);
      }
    }

    // ✅ ส่งผลลัพธ์กลับ
    const orders = filteredCart.map((item) => ({
      gameId: item.gameId,
      quantity: item.quantity,
      status: "completed",
      redeemCode: promoCode || "",
    }));

    res.json({
      success: true,
      newWallet: user.wallet - finalTotal,
      discount,
      total,
      finalTotal,
      orders,
    });
  } catch (err) {
    console.error("Checkout Error:", err);

    // 🧩 ระบบ Rollback ส่วนลด (ถ้าเคยอัปเดตแล้ว)
    if (promoCodeUsed && discountDocRef && discountData && userIdRolledBack) {
      try {
        const rollbackCount = Math.max((discountData.usedCount || 1) - 1, 0);
        await discountDocRef.update({
          usedCount: rollbackCount,
          usedBy: admin.firestore.FieldValue.arrayRemove(userIdRolledBack),
          isActive: true, // เปิดกลับไว้ก่อน
          updatedAt: new Date(),
        });
        console.log(
          `↩️ Rollback ส่วนลด ${discountData.code} คืนให้แล้ว (usedCount=${rollbackCount})`
        );
      } catch (rbErr) {
        console.error("⚠️ Rollback discount error:", rbErr);
      }
    }

    res.status(500).json({ success: false, message: "Server Error" });
  }
});


app.post("/api/users/cart/validate-promo", authenticateToken, async (req, res) => {
  try {
    const { promoCode, subtotal } = req.body;
    const userId = req.user.userId;

    if (!promoCode) {
      return res.json({ valid: false, message: "โปรดกรอกโค้ด" });
    }

    // ✅ ดึงข้อมูลโค้ดส่วนลดจาก Firestore โดยใช้ where + limit เพื่อลด quota
    const discountQuery = await db.collection("discounts")
      .where("code", "==", promoCode)
      .limit(1)
      .get();

    if (discountQuery.empty) {
      return res.json({ valid: false, message: "โค้ดไม่ถูกต้อง" });
    }

    // ✅ ดึงเอกสารตัวแรกจาก Query
    const discountDoc = discountQuery.docs[0];
    const data = discountDoc.data();
    const now = new Date();

    // ✅ แปลง expireAt เป็น Date (รองรับทั้ง Timestamp และ string)
    let expireDate = null;
    if (data.expireAt?.toDate) {
      expireDate = data.expireAt.toDate();
    } else if (typeof data.expireAt === "string") {
      expireDate = new Date(data.expireAt);
    }

    // ✅ ตรวจสอบวันหมดอายุ
    if (expireDate && expireDate < now) {
      return res.json({ valid: false, message: "โค้ดหมดอายุแล้ว" });
    }

    // ✅ ตรวจสอบยอดซื้อขั้นต่ำ
    if (subtotal && subtotal < (data.minSpend || 0)) {
      return res.json({ valid: false, message: `ขั้นต่ำสำหรับโค้ดนี้คือ ${data.minSpend}` });
    }

    // ✅ ตรวจสอบจำนวนครั้งที่ใช้ได้
    if (data.usageLimit && (data.usedCount || 0) >= data.usageLimit) {
      return res.json({ valid: false, message: "โค้ดนี้ใช้ครบจำนวนครั้งแล้ว" });
    }

    // ✅ ตรวจสอบว่า user เคยใช้หรือยัง
    if (data.usedBy?.includes(userId)) {
      return res.json({ valid: false, message: "คุณเคยใช้โค้ดนี้แล้ว" });
    }

    // ✅ ถ้าผ่านทุกเงื่อนไข
    res.json({
      valid: true,
      discountType: data.type, // "fixed" หรือ "percent"
      discountValue: data.value,
      message: "ใช้โค้ดสำเร็จ!"
    });

  } catch (err) {
    console.error("Validate Promo Error:", err);
    res.status(500).json({ valid: false, message: "เกิดข้อผิดพลาดจากเซิร์ฟเวอร์" });
  }
});