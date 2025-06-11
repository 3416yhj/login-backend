// controllers/passwordController.js
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const nodemailer = require('nodemailer');

// 비밀번호 재설정 이메일 발송
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    
    // 이메일로 사용자 찾기
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: '해당 이메일로 등록된 사용자가 없습니다.' });
    }
    
    // 비밀번호 재설정 토큰 생성
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    // 토큰 해시 저장
    user.resetPasswordToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    
    // 토큰 만료시간 설정 (15분)
    user.resetPasswordExpires = Date.now() + 15 * 60 * 1000;
    
    await user.save();
    
    // 비밀번호 재설정 이메일 발송
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
    
    const resetURL = `${process.env.BASE_URL}/reset-password.html?token=${resetToken}`;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: '비밀번호 재설정',
      html: `
        <h1>비밀번호 재설정</h1>
        <p>아래 링크를 클릭하여 비밀번호를 재설정하세요:</p>
        <a href="${resetURL}">비밀번호 재설정하기</a>
        <p>이 링크는 15분 후에 만료됩니다.</p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    res.status(200).json({ 
      message: '비밀번호 재설정 링크가 이메일로 발송되었습니다.' 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 비밀번호 재설정
exports.resetPassword = async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;
    
    // 비밀번호 일치 확인
    if (password !== confirmPassword) {
      return res.status(400).json({ message: '비밀번호가 일치하지 않습니다.' });
    }
    
    // 토큰 해시
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
    // 토큰과 만료시간으로 사용자 찾기
    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ 
        message: '잘못되었거나 만료된 토큰입니다. 다시 시도해주세요.' 
      });
    }
    
    // 새 비밀번호 설정
    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    
    await user.save();
    
    res.status(200).json({ 
      message: '비밀번호가 성공적으로 변경되었습니다. 로그인하세요.' 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};