////////////////////เพิ่มประเภทเกม 

// seed-categories.js
import admin from "firebase-admin";
import dotenv from "dotenv";

dotenv.config();

////โหลดค่า Firebase Key จาก .env
if (!process.env.FIREBASE_KEY) {
  console.error("❌ Missing FIREBASE_KEY in .env");
  process.exit(1);
}

////ต่อ Firebase 
const serviceAccount = JSON.parse(process.env.FIREBASE_KEY);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

////รายการประเภทเกม 7 ประเภท
const categories = [
  {
    name: "Action",
    description: "เกมแนวแอ็กชันที่ต้องใช้ความเร็ว ความแม่นยำ และทักษะในการต่อสู้",
  },
  {
    name: "Adventure",
    description: "เกมผจญภัย เน้นการสำรวจ การดำเนินเรื่อง และการแก้ปริศนา",
  },
  {
    name: "RPG ",
    description: "เกมบทบาทสมมติ ผู้เล่นสวมบทบาทตัวละคร มีเควสต์และระบบเลเวล",
  },
  {
    name: "FPS",
    description: "เกมยิงปืน เช่น FPS หรือ Battle Royale",
  },
  {
    name: "Sports",
    description: "เกมกีฬา เช่น ฟุตบอล บาสเกตบอล หรือแข่งรถ",
  },
  {
    name: "Simulation",
    description: "เกมจำลองสถานการณ์ เช่น ทำฟาร์ม ขับเครื่องบิน หรือสร้างเมือง",
  },
  {
    name: "Strategy",
    description: "เกมวางแผนกลยุทธ์ ใช้ทักษะคิด วิเคราะห์ และบริหารทรัพยากร",
  },
];

////ฟังก์ชันหลัก
async function seedCategories() {
  console.log("🚀 เริ่มเพิ่มประเภทเกมลง Firestore...");

  const batch = db.batch();
  const colRef = db.collection("categories");

  for (const cat of categories) {
    const docRef = colRef.doc(); ////Firestore สร้าง id ให้เอง
    batch.set(docRef, {
      ...cat,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  }

  await batch.commit();
  console.log(`✅ เพิ่มประเภทเกมทั้งหมด ${categories.length} รายการสำเร็จ!`);
  process.exit(0);
}

//เรียกใช้
seedCategories().catch((err) => {
  console.error("❌ เกิดข้อผิดพลาดในการเพิ่มข้อมูล:", err);
  process.exit(1);
});
