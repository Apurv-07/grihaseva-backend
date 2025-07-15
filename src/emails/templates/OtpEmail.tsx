
interface OtpEmailProps {
  otp: string | number;
}

const OtpEmail = ({ otp }: OtpEmailProps) => (
  <div>
    <h1 style={{ color: "blue" }}>Welcome!</h1>
    <p>Your OTP is: <strong style={{ color: "red", textDecoration: "underline" }}>{otp}</strong></p>
  </div>
);

export default OtpEmail;
