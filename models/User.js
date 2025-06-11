const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: [true, '아이디를 입력하세요.'], 
    unique: true,
    trim: true,
    minlength: [4, '아이디는 최소 4자 이상이어야 합니다.'],
    match: [/^[a-zA-Z0-9_]+$/, '아이디는 영문자, 숫자, 밑줄(_)만 포함할 수 있습니다.']
  },
  password: { 
    type: String, 
    required: [true, '비밀번호를 입력하세요.'],
    minlength: [6, '비밀번호는 최소 6자 이상이어야 합니다.'],
    select: false // 기본적으로 조회 시 비밀번호 필드 제외
  },
  name: { 
    type: String, 
    required: [true, '이름을 입력하세요.'],
    trim: true
  },
  phone: { 
    type: String, 
    required: [true, '전화번호를 입력하세요.'],
    trim: true,
    match: [/^[0-9\-+]+$/, '유효한 전화번호 형식을 입력하세요.']
  },
  email: { 
    type: String, 
    required: [true, '이메일을 입력하세요.'], 
    unique: true,
    trim: true,
    lowercase: true,
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      '유효한 이메일 주소를 입력하세요.'
    ]
  },
  birth: { 
    type: String 
  },
  isVerified: { 
    type: Boolean, 
    default: false 
  },
  verificationToken: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  role: { 
    type: String, 
    enum: ['user', 'admin'], 
    default: 'user' 
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// 비밀번호 검증 메소드
userSchema.methods.validatePassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

// 계정 잠금 체크
userSchema.methods.isLocked = function() {
  // 계정이 잠금되었고 잠금 시간이 아직 지나지 않았는지 확인
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// 로그인 시도 증가 및 계정 잠금 처리
userSchema.methods.incrementLoginAttempts = async function() {
  // 계정 잠금이 해제되었다면 시도 횟수 초기화
  if (this.lockUntil && this.lockUntil < Date.now()) {
    this.loginAttempts = 1;
    this.lockUntil = undefined;
    await this.save();
    return;
  }
  
  // 로그인 시도 횟수 증가
  this.loginAttempts += 1;
  
  // 최대 시도 횟수(5)를 초과하면 계정 잠금 (15분)
  if (this.loginAttempts >= 5) {
    this.lockUntil = Date.now() + 15 * 60 * 1000;
  }
  
  return await this.save();
};

// 로그인 성공 시 시도 횟수 초기화
userSchema.methods.resetLoginAttempts = async function() {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  this.lastLogin = Date.now();
  return await this.save();
};

// 저장 전 비밀번호 해싱
userSchema.pre('save', async function(next) {
  // 비밀번호가 변경되지 않은 경우 다음 미들웨어로
  if (!this.isModified('password')) return next();
  
  try {
    // 비밀번호 해싱 (10회 솔팅)
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

module.exports = mongoose.model('User', userSchema);