const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

exports.sendVerificationEmail = (to, token) => {
  const verificationLink = `${process.env.BASE_URL}/api/auth/verify?token=${token}`;
  return transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: '이메일 인증',
    html: `<p>이메일을 인증하려면 아래 링크를 클릭해주세요:</p><a href="${verificationLink}">인증하기</a>`,
  });
};

exports.sendVerificationResend = async (to, token) => {
  const verificationLink = `${process.env.BASE_URL}/api/auth/verify?token=${token}`;
  return transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: '이메일 인증 재발송',
    html: `<p>이메일을 인증하려면 아래 링크를 클릭해주세요:</p><a href="${verificationLink}">인증하기</a>`,
  });
};