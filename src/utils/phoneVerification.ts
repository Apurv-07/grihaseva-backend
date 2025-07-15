import twilio = require("twilio");
const client = twilio(
  process.env.TWILIO_ACCOUNT_SID!,
  process.env.TWILIO_AUTH_TOKEN!
);

export async function sendOtp(phone: string, otp: string) {
  console.log("phone inside send otp", phone);
  const verification = await client.messages.create({
      body: `🛡️ Your OTP for Grihaseva account verification is: ${otp}`,
      from: process.env.TWILIO_WHATSAPP_NUMBER,
      to: `whatsapp:${phone}`,
    });
  console.log("Status:", verification.status); // e.g. "pending"
  return verification.status;
}
