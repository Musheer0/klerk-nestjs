export const otpEmailTemplate = ({ otp }: { otp: string }) => `
  <div style="
    font-family: Arial, sans-serif;
    padding: 20px;
    border: 1px solid #eaeaea;
    border-radius: 8px;
    max-width: 400px;
    margin: auto;
    background-color: #fff;
  ">
    <h2 style="color: #333;">Your One-Time Password (OTP)</h2>
    <p style="font-size: 16px; color: #555;">
      Use the following OTP to verify your account:
    </p>
    <div style="
      font-size: 24px;
      font-weight: bold;
      background-color: #f4f4f4;
      padding: 10px 20px;
      border-radius: 6px;
      text-align: center;
      letter-spacing: 4px;
      margin: 20px 0;
    ">
      ${otp}
    </div>
    <p style="font-size: 14px; color: #999;">
      This code is valid for a limited time. If you did not request this, please ignore this email.
    </p>
  </div>
`;
