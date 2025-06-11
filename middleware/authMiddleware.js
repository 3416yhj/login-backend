const jwt = require('jsonwebtoken');
const User = require('../models/User');
// 토큰 검증 미들웨어
exports.verifyToken = async (req, res, next) => {
  try {
    // 토큰 가져오기 (헤더, 쿠키, 쿼리 등에서)
    let token;
    
    // Bearer 토큰 검증
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } 
    // 쿠키에서 토큰 확인
    else if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }
    
    // 토큰이 없는 경우
    if (!token) {
      return res.status(401).json({ 
        message: '로그인이 필요합니다.',
        isAuthenticated: false 
      });
    }
    // 토큰 검증
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // 사용자 데이터 조회
    const user = await User.findById(decoded.id).select('-password');
    if (!user) {
      return res.status(404).json({ 
        message: '사용자를 찾을 수 없습니다.',
        isAuthenticated: false
      });
    }
    
    // 이메일 미인증 사용자 차단
    if (!user.isVerified) {
      return res.status(403).json({ 
        message: '이메일 인증이 필요합니다.',
        isAuthenticated: false
      });
    }
    
    // 인증 성공: req 객체에 사용자 정보 추가
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        message: '유효하지 않은 토큰입니다.',
        isAuthenticated: false
      });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: '로그인 세션이 만료되었습니다. 다시 로그인해주세요.',
        isAuthenticated: false
      });
    }
    console.error('Auth middleware error:', error);
    res.status(500).json({ 
      message: '인증 처리 중 오류가 발생했습니다.',
      isAuthenticated: false
    });
  }
};
// 관리자 권한 확인 미들웨어
exports.isAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ 
      message: '관리자 권한이 필요합니다.',
      isAuthorized: false
    });
  }
  next();
};
// 본인 확인 미들웨어 (프로필 수정 등에 사용)
exports.isOwner = (req, res, next) => {
  const userId = req.params.id;
  
  // 관리자는 모든 사용자 데이터에 접근 가능
  if (req.user.role === 'admin') {
    return next();
  }
  
  // 본인 데이터만 접근 가능
  if (req.user.id !== userId) {
    return res.status(403).json({
      message: '본인의 데이터만 접근할 수 있습니다.',
      isAuthorized: false
    });
  }
  
  next();
};

// 특정 역할 권한 확인 미들웨어
exports.hasRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        message: '로그인이 필요합니다.',
        isAuthenticated: false
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        message: '접근 권한이 없습니다.',
        isAuthorized: false
      });
    }

    next();
  };
};

// 활성 계정 확인 미들웨어
exports.isActiveAccount = (req, res, next) => {
  if (!req.user.isActive) {
    return res.status(403).json({
      message: '계정이 비활성화되었습니다. 관리자에게 문의하세요.',
      isAuthorized: false
    });
  }
  
  next();
};

// 토큰 새로고침 미들웨어
exports.refreshToken = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    
    if (!refreshToken) {
      return next(); // 리프레시 토큰이 없으면 다음 미들웨어로
    }
    
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user || refreshToken !== user.refreshToken) {
      return next();
    }
    
    // 새 액세스 토큰 발급
    const accessToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );
    
    // 쿠키에 새 토큰 설정
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: parseInt(process.env.JWT_COOKIE_EXPIRES_IN) * 1000
    });
    
    next();
  } catch (error) {
    // 리프레시 토큰 오류는 무시하고 다음 미들웨어로
    next();
  }
};

// API 요청 제한 미들웨어 (사용자별)
exports.rateLimit = (limit, timeWindow) => {
  const requests = new Map();
  
  return (req, res, next) => {
    const userId = req.user ? req.user.id : req.ip;
    const now = Date.now();
    
    if (!requests.has(userId)) {
      requests.set(userId, []);
    }
    
    // 시간 윈도우 내의 요청만 유지
    const userRequests = requests.get(userId).filter(time => now - time < timeWindow);
    
    if (userRequests.length >= limit) {
      return res.status(429).json({
        message: '너무 많은 요청을 보냈습니다. 잠시 후 다시 시도해주세요.',
        retryAfter: Math.ceil((timeWindow - (now - userRequests[0])) / 1000)
      });
    }
    
    // 현재 요청 추가
    userRequests.push(now);
    requests.set(userId, userRequests);
    
    next();
  };
};