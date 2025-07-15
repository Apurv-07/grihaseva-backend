import twilio = require("twilio");
const client = twilio(
  process.env.TWILIO_ACCOUNT_SID!,
  process.env.TWILIO_AUTH_TOKEN!
);

export async function checkOtp(phone: string, code: string) {
  const verificationCheck = await client.verify.v2
    .services(process.env.TWILIO_VERIFY_SID!)
    .verificationChecks.create({
      to: phone,
      code,
    });
  console.log("Verified?", verificationCheck.status); // "approved" or "pending"
  return verificationCheck.status === "approved";
}

export async function sendOtp(phone: string) {
  console.log("phone inside send otp", phone);
  const verification = await client.verify.v2
    .services(process.env.TWILIO_VERIFY_SID!)
    .verifications.create({
      channel: "sms",
      to: phone,
    });
  console.log("Status:", verification.status); // e.g. "pending"
  return verification.status === "pending";
}
