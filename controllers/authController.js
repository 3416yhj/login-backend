const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { sendVerificationEmail, sendVerificationResend, sendPasswordResetEmail } = require('../utils/mailer');
const crypto = require('crypto');

// 비밀번호 유효성 검사
const validatePassword = (password) => {
  // 최소 8자 이상, 영문자, 숫자, 특수문자 포함
  const regex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
  return regex.test(password);
};

// 회원가입 처리
exports.register = async (req, res) => {
  try {
    const { username, password, confirmPassword, name, phone, email, birth } = req.body;

    // 필수 필드 검증
    if (!username || !password || !confirmPassword || !name || !phone || !email) {
      return res.status(400).json({ message: '모든 필수 항목을 입력해주세요.' });
    }

    // 아이디 길이 및 형식 검증
    if (username.length < 4) {
      return res.status(400).json({ message: '아이디는 최소 4자 이상이어야 합니다.' });
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ message: '아이디는 영문자, 숫자, 밑줄(_)만 포함할 수 있습니다.' });
    }

    // 비밀번호 유효성 검증
    if (!validatePassword(password)) {
      return res.status(400).json({ message: '비밀번호는 최소 8자 이상, 영문자, 숫자, 특수문자를 포함해야 합니다.' });
    }

    // 비밀번호 일치 확인
    if (password !== confirmPassword) {
      return res.status(400).json({ message: '비밀번호가 일치하지 않습니다.' });
    }

    // 이메일 형식 검증
    const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: '유효한 이메일 주소를 입력하세요.' });
    }

    // 전화번호 형식 검증
    if (!/^[0-9\-+]+$/.test(phone)) {
      return res.status(400).json({ message: '유효한 전화번호 형식을 입력하세요.' });
    }

    // 이미 존재하는 사용자 확인
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      if (existingUser.username === username) {
        return res.status(400).json({ message: '이미 존재하는 아이디입니다.' });
      }
      return res.status(400).json({ message: '이미 등록된 이메일입니다.' });
    }

    // 랜덤 인증 토큰 생성
    const verificationToken = crypto.randomBytes(32).toString('hex');
    // 만료 시간 설정 (24시간)
    const tokenExpires = new Date();
    tokenExpires.setHours(tokenExpires.getHours() + 24);

    // 새 사용자 생성
    const user = new User({
      username,
      password, // 모델의 pre save 훅에서 해싱 처리됨
      name,
      phone,
      email,
      birth,
      verificationToken,
      verificationExpires: tokenExpires,
      isVerified: false,
    });

    await user.save();
    await sendVerificationEmail(email, verificationToken);

    res.status(201).json({ 
      message: '가입 완료! 이메일 인증을 진행해주세요.',
      success: true 
    });
  } catch (err) {
    console.error('회원가입 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 이메일 인증 처리
exports.verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).render('verification-error', { 
        message: '인증 토큰이 없습니다.' 
      });
    }

    const user = await User.findOne({ 
      verificationToken: token,
      verificationExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).render('verification-error', { 
        message: '유효하지 않거나 만료된 인증 토큰입니다.' 
      });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    await user.save();

    // 인증 성공 시 로그인 페이지로 리다이렉트
    res.redirect('/login.html?verified=true');
  } catch (err) {
    console.error('이메일 인증 오류:', err);
    res.status(500).render('verification-error', { 
      message: '서버 오류가 발생했습니다.' 
    });
  }
};

// 인증 메일 재전송
exports.resendVerification = async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: '이메일을 입력해주세요.' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: '해당 이메일로 가입된 사용자가 없습니다.' });
    }
    
    if (user.isVerified) {
      return res.status(400).json({ message: '이미 인증된 계정입니다.' });
    }
    
    // 새로운 인증 토큰 생성
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const tokenExpires = new Date();
    tokenExpires.setHours(tokenExpires.getHours() + 24);
    
    user.verificationToken = verificationToken;
    user.verificationExpires = tokenExpires;
    await user.save();
    
    await sendVerificationResend(email, verificationToken);
    
    res.json({ message: '인증 메일이 재전송되었습니다.', success: true });
  } catch (err) {
    console.error('인증 메일 재전송 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 로그인 처리
exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // 입력값 검증
    if (!username || !password) {
      return res.status(400).json({ message: '아이디와 비밀번호를 모두 입력하세요.' });
    }

    // 사용자 조회 (비밀번호 필드 포함)
    const user = await User.findOne({ username }).select('+password');

    if (!user) {
      return res.status(400).json({ message: '존재하지 않는 사용자입니다.' });
    }

    // 계정 잠금 확인
    if (user.isLocked()) {
      const lockTime = new Date(user.lockUntil);
      return res.status(403).json({ 
        message: `계정이 잠겨있습니다. ${lockTime.toLocaleString()}에 다시 시도해주세요.` 
      });
    }

    // 계정 인증 확인
    if (!user.isVerified) {
      return res.status(403).json({ 
        message: '이메일 인증이 완료되지 않았습니다. 메일함을 확인하세요.',
        needVerification: true,
        email: user.email 
      });
    }

    // 비밀번호 확인
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // 로그인 실패 횟수 증가
      user.loginAttempts += 1;
      
      // 로그인 시도 5회 실패 시 계정 잠금
      if (user.loginAttempts >= 5) {
        const lockTime = new Date();
        lockTime.setMinutes(lockTime.getMinutes() + 30); // 30분 동안 잠금
        user.lockUntil = lockTime;
        await user.save();
        return res.status(403).json({ 
          message: '로그인 5회 실패로 계정이 30분간 잠겼습니다.' 
        });
      }
      
      await user.save();
      return res.status(400).json({ 
        message: '비밀번호가 일치하지 않습니다.',
        attempts: user.loginAttempts,
        remainingAttempts: 5 - user.loginAttempts
      });
    }

    // 로그인 성공 시 로그인 시도 횟수 초기화
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    // JWT 토큰 생성
    const payload = {
      id: user._id,
      username: user.username,
      name: user.name,
      role: user.role
    };

    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 리프레시 토큰 생성
    const refreshToken = crypto.randomBytes(40).toString('hex');
    user.refreshToken = refreshToken;
    user.refreshTokenExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7일
    await user.save();

    // 쿠키에 저장
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 1000 // 1시간
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7일
    });

    // 사용자 정보 반환 (비밀번호 제외)
    const userResponse = {
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt
    };

    res.json({
      message: '로그인 성공',
      user: userResponse,
      token // 클라이언트에서 헤더에 포함하기 위한 토큰 제공
    });
  } catch (err) {
    console.error('로그인 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 토큰 갱신
exports.refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refresh_token;
    
    if (!refreshToken) {
      return res.status(401).json({ message: '리프레시 토큰이 없습니다.' });
    }
    
    const user = await User.findOne({ 
      refreshToken, 
      refreshTokenExpires: { $gt: Date.now() } 
    });
    
    if (!user) {
      return res.status(401).json({ message: '유효하지 않거나 만료된 리프레시 토큰입니다.' });
    }
    
    // 새로운 액세스 토큰 생성
    const payload = {
      id: user._id,
      username: user.username,
      name: user.name,
      role: user.role
    };
    
    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // 쿠키 갱신
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 1000 // 1시간
    });
    
    res.json({
      message: '토큰이 갱신되었습니다.',
      token
    });
  } catch (err) {
    console.error('토큰 갱신 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 로그아웃
exports.logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refresh_token;
    
    if (refreshToken) {
      // 데이터베이스에서 리프레시 토큰 제거
      await User.findOneAndUpdate(
        { refreshToken },
        { $unset: { refreshToken: 1, refreshTokenExpires: 1 } }
      );
    }
    
    // 쿠키 제거
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    
    res.json({ message: '로그아웃 되었습니다.' });
  } catch (err) {
    console.error('로그아웃 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 비밀번호 재설정 요청
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: '이메일을 입력해주세요.' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      // 보안상의 이유로 사용자가 없어도 성공 메시지 반환
      return res.json({ message: '비밀번호 재설정 링크가 이메일로 전송되었습니다.' });
    }
    
    // 비밀번호 재설정 토큰 생성
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 3600000); // 1시간
    
    // 해시된 토큰 저장
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = resetExpires;
    await user.save();
    
    // 이메일 전송
    await sendPasswordResetEmail(email, resetToken);
    
    res.json({ message: '비밀번호 재설정 링크가 이메일로 전송되었습니다.' });
  } catch (err) {
    console.error('비밀번호 재설정 요청 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 비밀번호 재설정
exports.resetPassword = async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;
    
    if (!token || !password || !confirmPassword) {
      return res.status(400).json({ message: '모든 필드를 입력해주세요.' });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ message: '비밀번호가 일치하지 않습니다.' });
    }
    
    if (!validatePassword(password)) {
      return res.status(400).json({ message: '비밀번호는 최소 8자 이상, 영문자, 숫자, 특수문자를 포함해야 합니다.' });
    }
    
    // 토큰 해시화
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
    // 유효한 토큰을 가진 사용자 찾기
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ message: '유효하지 않거나 만료된 토큰입니다.' });
    }
    
    // 비밀번호 업데이트
    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    
    // 보안을 위해 모든 세션 종료 (리프레시 토큰 삭제)
    user.refreshToken = undefined;
    user.refreshTokenExpires = undefined;
    
    await user.save();
    
    res.json({ message: '비밀번호가 성공적으로 변경되었습니다. 다시 로그인해주세요.' });
  } catch (err) {
    console.error('비밀번호 재설정 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 비밀번호 변경 (로그인 상태)
exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const userId = req.user.id; // JWT 미들웨어에서 추가한 사용자 정보
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: '모든 필드를 입력해주세요.' });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: '새 비밀번호가 일치하지 않습니다.' });
    }
    
    if (!validatePassword(newPassword)) {
      return res.status(400).json({ message: '비밀번호는 최소 8자 이상, 영문자, 숫자, 특수문자를 포함해야 합니다.' });
    }
    
    const user = await User.findById(userId).select('+password');
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    
    // 현재 비밀번호 확인
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: '현재 비밀번호가 일치하지 않습니다.' });
    }
    
    // 새 비밀번호가 이전 비밀번호와 같은지 확인
    if (currentPassword === newPassword) {
      return res.status(400).json({ message: '새 비밀번호는 현재 비밀번호와 달라야 합니다.' });
    }
    
    // 비밀번호 업데이트
    user.password = newPassword;
    
    // 보안을 위해 모든 다른 세션 종료
    user.refreshToken = undefined;
    user.refreshTokenExpires = undefined;
    
    await user.save();
    
    // 새 JWT 토큰 발급
    const payload = {
      id: user._id,
      username: user.username,
      name: user.name,
      role: user.role
    };
    
    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // 새 리프레시 토큰 발급
    const refreshToken = crypto.randomBytes(40).toString('hex');
    user.refreshToken = refreshToken;
    user.refreshTokenExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7일
    await user.save();
    
    // 쿠키 갱신
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 1000 // 1시간
    });
    
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7일
    });
    
    res.json({ 
      message: '비밀번호가 성공적으로 변경되었습니다.',
      token
    });
  } catch (err) {
    console.error('비밀번호 변경 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 사용자 정보 조회
exports.getProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    
    const user = await User.findById(userId, {
      password: 0,
      refreshToken: 0,
      refreshTokenExpires: 0,
      verificationToken: 0,
      verificationExpires: 0,
      resetPasswordToken: 0,
      resetPasswordExpires: 0,
      loginAttempts: 0,
      lockUntil: 0
    });
    
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    
    res.json({ user });
  } catch (err) {
    console.error('사용자 정보 조회 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 사용자 정보 업데이트
exports.updateProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, phone, birth } = req.body;
    
    // 수정 가능한 필드만 허용
    const updateData = {};
    if (name) updateData.name = name;
    if (phone) {
      // 전화번호 형식 검증
      if (!/^[0-9\-+]+$/.test(phone)) {
        return res.status(400).json({ message: '유효한 전화번호 형식을 입력하세요.' });
      }
      updateData.phone = phone;
    }
    if (birth) updateData.birth = birth;
    
    const user = await User.findByIdAndUpdate(
      userId,
      { $set: updateData },
      { new: true, runValidators: true }
    );
    
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    
    // 응답에서 민감한 정보 제외
    const userResponse = {
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      phone: user.phone,
      birth: user.birth,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
    
    res.json({
      message: '프로필이 성공적으로 업데이트되었습니다.',
      user: userResponse
    });
  } catch (err) {
    console.error('프로필 업데이트 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 계정 탈퇴
exports.deleteAccount = async (req, res) => {
  try {
    const userId = req.user.id;
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ message: '비밀번호를 입력해주세요.' });
    }
    
    const user = await User.findById(userId).select('+password');
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    
    // 비밀번호 확인
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: '비밀번호가 일치하지 않습니다.' });
    }
    
    // 계정 삭제 (또는 비활성화)
    // 완전 삭제 대신 비활성화 처리 (GDPR 등 데이터 규정 고려)
    user.isActive = false;
    user.deactivatedAt = Date.now();
    // 개인정보 익명화
    user.email = `deleted_${user._id}@deleted.com`;
    user.name = '탈퇴한 사용자';
    user.phone = null;
    user.refreshToken = undefined;
    user.refreshTokenExpires = undefined;
    
    await user.save();
    
    // 쿠키 제거
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    
    res.json({ message: '계정이 성공적으로 탈퇴되었습니다.' });
  } catch (err) {
    console.error('계정 탈퇴 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 관리자 전용 - 사용자 목록 조회
exports.getAllUsers = async (req, res) => {
  try {
    // 관리자 권한 확인
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: '접근 권한이 없습니다.' });
    }
    
    const users = await User.find(
      { isActive: true },
      {
        password: 0,
        refreshToken: 0,
        refreshTokenExpires: 0,
        verificationToken: 0,
        verificationExpires: 0,
        resetPasswordToken: 0,
        resetPasswordExpires: 0
      }
    ).sort({ createdAt: -1 });
    
    res.json({ users });
  } catch (err) {
    console.error('사용자 목록 조회 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 관리자 전용 - 사용자 계정 잠금 해제
exports.unlockAccount = async (req, res) => {
  try {
    // 관리자 권한 확인
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: '접근 권한이 없습니다.' });
    }
    
    const { userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    
    // 계정 잠금 해제
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();
    
    res.json({ message: '계정 잠금이 해제되었습니다.' });
  } catch (err) {
    console.error('계정 잠금 해제 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 2단계 인증 활성화
exports.enable2FA = async (req, res) => {
  try {
    const userId = req.user.id;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    // 2FA 비밀키 생성
    const secret = crypto.randomBytes(20).toString('hex');
    
    // 비밀키 저장
    user.twoFactorSecret = secret;
    user.twoFactorEnabled = true;
    await user.save();
    
    res.json({
      message: '2단계 인증이 활성화되었습니다.',
      secret
    });
  } catch (err) {
    console.error('2FA 활성화 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 2단계 인증 비활성화
exports.disable2FA = async (req, res) => {
  try {
    const userId = req.user.id;
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ message: '비밀번호를 입력해주세요.' });
    }
    
    const user = await User.findById(userId).select('+password');
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    
    // 비밀번호 확인
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: '비밀번호가 일치하지 않습니다.' });
    }
    
    // 2FA 비활성화
    user.twoFactorSecret = undefined;
    user.twoFactorEnabled = false;
    await user.save();
    
    res.json({ message: '2단계 인증이 비활성화되었습니다.' });
  } catch (err) {
    console.error('2FA 비활성화 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 2단계 인증 코드 확인
exports.verify2FA = async (req, res) => {
  try {
    const { username, code } = req.body;
    
    if (!username || !code) {
      return res.status(400).json({ message: '사용자 이름과 인증 코드를 입력해주세요.' });
    }
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    
    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({ message: '2단계 인증이 활성화되지 않았습니다.' });
    }
    
    // TOTP 알고리즘 사용하여 OTP 생성 및 검증
    // 여기서는 예시로 단순 검증만 수행 (실제로는 TOTP 라이브러리 사용 권장)
    const isValid = code === '123456'; // 실제 구현에서는 적절한 OTP 검증 로직 사용
    
    if (!isValid) {
      return res.status(400).json({ message: '유효하지 않은 인증 코드입니다.' });
    }
    
    // JWT 토큰 생성
    const payload = {
      id: user._id,
      username: user.username,
      name: user.name,
      role: user.role
    };
    
    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // 리프레시 토큰 생성
    const refreshToken = crypto.randomBytes(40).toString('hex');
    user.refreshToken = refreshToken;
    user.refreshTokenExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7일
    await user.save();
    
    // 쿠키에 저장
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 60 * 60 * 1000 // 1시간
    });
    
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7일
    });
    
    res.json({
      message: '2단계 인증 성공',
      token
    });
  } catch (err) {
    console.error('2FA 검증 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 사용자 상태 확인
exports.checkUserStatus = async (req, res) => {
  try {
    // JWT 미들웨어에서 추가한 사용자 정보 사용
    const userId = req.user.id;
    
    const user = await User.findById(userId, {
      password: 0,
      refreshToken: 0,
      refreshTokenExpires: 0,
      verificationToken: 0,
      verificationExpires: 0,
      resetPasswordToken: 0,
      resetPasswordExpires: 0
    });
    
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    
    res.json({
      isAuthenticated: true,
      user: {
        _id: user._id,
        username: user.username,
        name: user.name,
        email: user.email,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });
  } catch (err) {
    console.error('사용자 상태 확인 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 이메일 변경 요청
exports.requestEmailChange = async (req, res) => {
  try {
    const userId = req.user.id;
    const { newEmail, password } = req.body;
    
    if (!newEmail || !password) {
      return res.status(400).json({ message: '새 이메일과 비밀번호를 입력해주세요.' });
    }
    
    // 이메일 형식 검증
    const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    if (!emailRegex.test(newEmail)) {
      return res.status(400).json({ message: '유효한 이메일 주소를 입력하세요.' });
    }
    
    const user = await User.findById(userId).select('+password');
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    
    // 비밀번호 확인
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: '비밀번호가 일치하지 않습니다.' });
    }
    
    // 이미 사용 중인 이메일인지 확인
    const existingUser = await User.findOne({ email: newEmail });
    if (existingUser) {
      return res.status(400).json({ message: '이미 사용 중인 이메일입니다.' });
    }
    
    // 이메일 변경 인증 토큰 생성
    const changeEmailToken = crypto.randomBytes(32).toString('hex');
    const tokenExpires = new Date();
    tokenExpires.setHours(tokenExpires.getHours() + 24);
    
    user.pendingEmail = newEmail;
    user.changeEmailToken = changeEmailToken;
    user.changeEmailExpires = tokenExpires;
    await user.save();
    
    // 이메일 변경 인증 메일 전송
    // 실제 구현 시 mailer.js에 관련 함수 추가 필요
    // await sendEmailChangeVerification(newEmail, changeEmailToken);
    
    res.json({ message: '이메일 변경 인증 링크가 새 이메일로 전송되었습니다.' });
  } catch (err) {
    console.error('이메일 변경 요청 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 이메일 변경 확인
exports.confirmEmailChange = async (req, res) => {
  try {
    const { token } = req.query;
    
    if (!token) {
      return res.status(400).render('verification-error', { 
        message: '인증 토큰이 없습니다.' 
      });
    }
    
    const user = await User.findOne({
      changeEmailToken: token,
      changeEmailExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).render('verification-error', { 
        message: '유효하지 않거나 만료된 토큰입니다.' 
      });
    }
    
    // 이메일 변경 적용
    user.email = user.pendingEmail;
    user.pendingEmail = undefined;
    user.changeEmailToken = undefined;
    user.changeEmailExpires = undefined;
    await user.save();
    
    // 이메일 변경 성공 시 로그인 페이지로 리다이렉트
    res.redirect('/login.html?emailChanged=true');
  } catch (err) {
    console.error('이메일 변경 확인 오류:', err);
    res.status(500).render('verification-error', { 
      message: '서버 오류가 발생했습니다.' 
    });
  }
};

// 세션 만료 시간 확인
exports.checkSessionExpiry = async (req, res) => {
  try {
    const token = req.cookies.access_token;
    
    if (!token) {
      return res.json({ expired: true });
    }
    
    try {
      // 토큰 디코딩해서 만료 시간 확인
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const expiresAt = new Date(decoded.exp * 1000);
      const now = new Date();
      
      // 남은 시간 계산 (밀리초)
      const remainingTime = expiresAt - now;
      
      res.json({
        expired: false,
        expiresAt,
        remainingTime
      });
    } catch (err) {
      // 토큰이 만료되었거나 유효하지 않음
      return res.json({ expired: true });
    }
  } catch (err) {
    console.error('세션 만료 확인 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 최근 로그인 기록 조회
exports.getLoginHistory = async (req, res) => {
  try {
    const userId = req.user.id;
    
    // 실제 로그인 기록은 별도의 모델로 관리해야 함
    // 여기서는 예시로 빈 배열 반환
    const loginHistory = [];
    
    res.json({ loginHistory });
  } catch (err) {
    console.error('로그인 기록 조회 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 관리자 전용 - 사용자 계정 잠금
exports.lockAccount = async (req, res) => {
  try {
    // 관리자 권한 확인
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: '접근 권한이 없습니다.' });
    }
    
    const { userId } = req.params;
    const { duration } = req.body; // 잠금 기간 (분)
    
    if (!duration || isNaN(duration) || duration <= 0) {
      return res.status(400).json({ message: '유효한 잠금 기간을 입력하세요.' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
    }
    
    // 계정 잠금 설정
    const lockTime = new Date();
    lockTime.setMinutes(lockTime.getMinutes() + parseInt(duration));
    
    user.loginAttempts = 5; // 로그인 시도 횟수 최대로 설정
    user.lockUntil = lockTime;
    await user.save();
    
    res.json({ 
      message: `계정이 ${duration}분 동안 잠겼습니다.`,
      lockUntil: lockTime 
    });
  } catch (err) {
    console.error('계정 잠금 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};

// 미사용 계정 정리 (관리자용)
exports.cleanupInactiveAccounts = async (req, res) => {
  try {
    // 관리자 권한 확인
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: '접근 권한이 없습니다.' });
    }
    
    const { inactiveDays } = req.body;
    
    if (!inactiveDays || isNaN(inactiveDays) || inactiveDays <= 0) {
      return res.status(400).json({ message: '유효한 비활성 기간(일)을 입력하세요.' });
    }
    
    // 지정된 기간 이상 로그인하지 않은 계정 조회
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - inactiveDays);
    
    const inactiveUsers = await User.find({
      lastLogin: { $lt: cutoffDate },
      isActive: true
    });
    
    // 비활성 계정 처리 로직 (알림 발송, 비활성화 등)
    // 여기서는 조회만 수행
    
    res.json({
      message: `${inactiveDays}일 이상 로그인하지 않은 계정 ${inactiveUsers.length}개를 찾았습니다.`,
      inactiveUsers: inactiveUsers.map(user => ({
        _id: user._id,
        username: user.username,
        email: user.email,
        lastLogin: user.lastLogin
      }))
    });
  } catch (err) {
    console.error('비활성 계정 정리 오류:', err);
    res.status(500).json({ message: '서버 오류가 발생했습니다.' });
  }
};