const express = require('express');
const bcrypt = require('bcryptjs'); // bcryptjs 사용
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authController = require('../controllers/authController');
const passwordController = require('../controllers/passwordController');

const router = express.Router();

// 회원가입
router.post('/register', async (req, res) => {
  try {
    const { username, password, email, name, phone, birth } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: '이미 사용 중인 아이디입니다.' });
    }

    const newUser = new User({
      username,
      password,
      email,
      name,
      phone,
      birth,
      verified: false,
    });

    await newUser.save();
    res.status(201).json({ message: '회원가입 성공!' });
  } catch (err) {
    res.status(500).json({ message: '서버 오류: ' + err.message });
  }
});

// 로그인
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. 입력값 유효성 검사
    if (!username || !password) {
      return res.status(400).json({ message: '아이디와 비밀번호를 모두 입력해주세요.' });
    }

    // 2. 사용자 조회 (password 포함해서 가져오기)
    const user = await User.findOne({ username }).select('+password');
    if (!user) {
      return res.status(400).json({ message: '사용자를 찾을 수 없습니다.' });
    }

    // 3. 비밀번호 비교
    if (!user.password) {
      return res.status(500).json({ message: '비밀번호 정보가 없습니다.' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: '비밀번호가 일치하지 않습니다.' });
    }

    // 4. JWT 발급
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 비밀번호는 응답에서 제외
    const { password: pw, ...userWithoutPassword } = user._doc;

    res.json({ message: '로그인 성공', token, user: userWithoutPassword });
  } catch (err) {
    console.error('로그인 오류:', err);
    res.status(500).json({ message: '서버 오류: ' + err.message });
  }
});

// 이메일 인증
router.get('/verify', authController.verifyEmail);

// 인증 메일 재발송
router.post('/resend', authController.resendVerification);

// 비밀번호 찾기 (재설정 메일 발송)
router.post('/forgot-password', passwordController.forgotPassword);

// 비밀번호 재설정
router.post('/reset-password', passwordController.resetPassword);

module.exports = router;