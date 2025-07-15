import { Router } from "express";
import { logoutUser, refreshUser, sendOtpMobile, userLogin, userRegistration, verifyOtpMobile, verifyUser, verifyUserOtp } from "../controllers/userController";
import { asyncHandler } from "../utils/asyncHandler";
// const app=express();
const router = Router();
// const router=express.Router();

// router.post('/send-otp-email', asyncHandler(verifyUser));
router.post('/send-otp-email', asyncHandler(verifyUser));
router.post('/verify-otp', asyncHandler(verifyUserOtp));
router.post('/send-otp-mobile', asyncHandler(sendOtpMobile))
router.post('/verify-otp-mobile', asyncHandler(verifyOtpMobile))
router.post("/register", asyncHandler(userRegistration));
router.post("/login", asyncHandler(userLogin));
router.post("/refresh", asyncHandler(refreshUser));
router.post("/logout", asyncHandler(logoutUser));

export default router;
