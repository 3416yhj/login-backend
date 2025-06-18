require('dotenv').config(); // .env 먼저 로드

const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth');
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어 설정
app.use(cors({
  origin: "https://apsi.netlify.app/login/login", // 또는 true (전체 허용)
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // 정적 파일 폴더

// 라우트
app.use('/api/auth', authRoutes);

// 기본 라우트
app.get("/", (req, res) => {
  res.send("백엔드 서버가 잘 작동 중이야.");
});

// MongoDB 연결
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/finexo', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('MongoDB 연결 성공');

  // DB 연결 후 서버 시작
  app.listen(PORT, () => {
    console.log(`서버가 포트 ${PORT}에서 실행 중이야`);
  });
})
.catch(err => {
  console.error('MongoDB 연결 실패:', err);
});