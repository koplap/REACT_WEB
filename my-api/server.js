const express = require('express');
const pool = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// ตรวจสอบ user token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // รับ token จาก header
  if (!token) return res.sendStatus(401); // ถ้าไม่มี token ส่ง status 401
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // ถ้า token ไม่ถูกต้อง ส่ง status 403
    req.user = user; // เก็บข้อมูล user ไว้ใน req
    next(); // ดำเนินการต่อไป
  });
};

// ดึงข้อมูลผู้ใช้งานที่เข้าเข้าระบบ Account
app.get('/account' , authenticateToken, async (req, res) => {
  try {
    const userid = req.user.id;
    const [results] = await pool.query("SELECT email, name, picture FROM users WHERE id =?", [userid])
    if(results.length === 0) {
      return res.status(404).json({error: "ไม่พบผู้ใช้"})
    }
    res.json(results)
  }catch (err) {
    console.log(err)
    res.status(500).json({ error: "ผิดพลาด"})
  }
})

const PORT = 4000;

app.post('/register', async (req, res) => {
  const { email, password, name } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  try {
    const [result] = await pool.query(
      'INSERT INTO users (email, password, name) VALUES (?, ?, ?)', 
      [email, hashedPassword, name]
    );
    res.status(201).send('User registered');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error registering user');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const [results] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = results[0];
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // เปรียบเทียบรหัสผ่าน
    if (await bcrypt.compare(password, user.password)) {
      const accessToken = jwt.sign(
        { id: user.id, email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '20h' }
      );
      return res.json({ token: accessToken });
    } else {
      return res.status(401).json({ message: 'Password incorrect' });
    }
    
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Error logging in' });
  }
});

app.post('/addnew', async (req, res) => {
  const { fname, lname } = req.body;
  
  try {
    // ใส่ข้อมูลลงในฐานข้อมูล
    const [result] = await pool.query(
      'INSERT INTO employees (fname, lname) VALUES (?, ?)', 
      [fname, lname]
    );
    res.status(201).send('User registered'); // แก้ไขข้อความ 'Uesr' เป็น 'User'
  } catch (error) {
    console.error(error); // แสดงข้อผิดพลาดใน console
    res.status(500).send('Error registering user'); // แก้ไขข้อความ error response
  }
});
// กำหนดโฟลเดอร์สำหรับเก็บรูป
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
      cb(null, 'uploads/')
  },
  filename: function(req, file, cb) {
      cb(null, Date.now() + path.extname(file.originalname))
  }
})



const upload = multer({ storage: storage });
// เปิดให้เข้าถึงไฟล์จากโฟลเดอร์ 'uploads'
app.use('/uploads', express.static('uploads'));
// เริ่มเซิร์ฟเวอร์ที่ port 4000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});