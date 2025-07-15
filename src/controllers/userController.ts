import * as React from "react";
import prisma from "../lib/lib.prisma";
import { Request, Response, NextFunction } from "express";
import {
  AddressSchema,
  RegisterUserSchema,
  TempSessionSchema,
} from "../types/userTypes";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import z from "zod";
import generateToken from "../utils/generateToken";
import { Resend } from "resend";
import { render } from "@react-email/render";
import OtpEmail from "../emails/templates/OtpEmail";
import { sendOtp } from "../utils/phoneVerification";

// const resend = new Resend("re_xxxxxxxxx");
const resend = new Resend(process.env.RESEND_API_KEY);

const userRegistration = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { name, email, password, phone, dob } = RegisterUserSchema.parse(
      req.body
    );
    // const address = AddressSchema.parse(req.body.address);

    const tempSession = await prisma.tempSession.findFirst({
      where: {
        OR: [{ email }, { phone }],
        verified: true,
      },
    });

    if (!tempSession) {
      return res.status(400).json({
        message: "Please verify your email or phone before registering",
      });
    }

    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ email }, { phone }],
      },
    });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }
    const userData: any = {
      name,
      password: await bcrypt.hash(password, 10),
      dob: new Date(dob),
    };

    if (email) {
      userData.email = email;
      userData.emailVerified = true;
    }
    if (phone) {
      userData.phone = phone;
      userData.phoneVerified = true;
    }

    if (!userData.email && !userData.phone) {
      return res
        .status(400)
        .json({ message: "Either email or phone is required" });
    }

    const user = await prisma.user.create({ data: userData });

    const authToken = generateToken(user.id, "1h");
    const refreshToken = generateToken(user.id, "7d");

    if (authToken && refreshToken) {
      await prisma.user.update({
        where: { id: user.id },
        data: { refreshToken },
      });
    }
    await prisma.tempSession.delete({
      where: { id: tempSession.id },
    });

    return res
      .status(201)
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({ authToken, message: "User created successfully" });
  } catch (e: any) {
    if (e instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation failed", errors: e.errors });
    }

    return res.status(500).json({ message: e.message });
  }
};

const verifyUser = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email } = TempSessionSchema.pick({ email: true }).parse(req.body);

    const existingSession = await prisma.tempSession.findUnique({
      where: { email },
    });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    if (existingSession) {
      if (existingSession.verified) {
        return res.status(400).json({ message: "User already verified" });
      }

      if (
        existingSession.otpExpires &&
        existingSession.otpExpires > new Date()
      ) {
        return res.status(400).json({
          message: "OTP already sent. Please wait before requesting again.",
        });
      }

      // OTP expired, resend with update
      await prisma.tempSession.update({
        where: { email },
        data: {
          otp,
          otpExpires: new Date(Date.now() + 1000 * 60 * 5), // 5 mins
        },
      });
    } else {
      await prisma.tempSession.create({
        data: {
          email,
          otp,
          otpExpires: new Date(Date.now() + 1000 * 60 * 5),
        },
      });
    }

    const { data, error } = await resend.emails.send({
      from: "Acme <onboarding@resend.dev>",
      to: [email],
      subject: "Your OTP Code",
      html: await render(React.createElement(OtpEmail, { otp })),
    });

    if (error) {
      return res.status(400).json({ message: "Failed to send OTP", error });
    }

    return res.status(200).json({ message: "OTP sent successfully" });
  } catch (e: any) {
    return res.status(500).json({ message: e.message });
  }
};

const verifyUserOtp = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { otp } = TempSessionSchema.pick({ otp: true }).parse(req.body);

    const session = await prisma.tempSession.findFirst({
      where: {
        otp,
        verified: false,
      },
    });

    if (!session) {
      return res.status(400).json({ message: "Invalid or already used OTP" });
    }

    if (session.otpExpires && session.otpExpires < new Date()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    await prisma.tempSession.update({
      where: { id: session.id },
      data: { verified: true },
    });

    return res.status(200).json({
      message: "OTP verified successfully",
      id: session.id,
    });
  } catch (e: any) {
    return res.status(500).json({ message: e.message });
  }
};

const userLogin = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email } = RegisterUserSchema.pick({ email: true }).parse(req.body);
    const { password } = RegisterUserSchema.pick({ password: true }).parse(
      req.body
    );
    const { phone } = RegisterUserSchema.pick({ phone: true }).parse(req.body);
    const user = await prisma.user.findFirst({
      where: {
        OR: [{ email }, { phone }],
      },
    });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid password" });
    }
    const authToken = generateToken(user.id, "1h");
    const refreshToken = generateToken(user.id, "7d");
    if (authToken && refreshToken) {
      await prisma.user.update({
        where: { id: user.id },
        data: { refreshToken },
      });
    }
    return res
      .status(200)
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({ authToken, message: "Login successful" });
  } catch (e: any) {
    if (e instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation failed", errors: e.errors });
    }
    return res.status(500).json({ message: e.message });
  }
};

const refreshUser = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET!);
    const user = await prisma.user.findUnique({
      where: { id: (decoded as jwt.JwtPayload).id },
    });
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const authToken = generateToken(user.id, "1h");
    const newRefreshToken = generateToken(user.id, "7d");
    if (authToken && newRefreshToken) {
      await prisma.user.update({
        where: { id: user.id },
        data: { refreshToken: newRefreshToken },
      });
    }
    return res
      .status(200)
      .cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({ authToken, message: "Token refreshed" });
  } catch (e: any) {
    return res.status(500).json({ message: e.message });
  }
};

const logoutUser = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET!);
    const deleted = await prisma.user.update({
      where: { id: (decoded as jwt.JwtPayload).id },
      data: { refreshToken: null },
    });
    if (!deleted) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    return res
      .status(200)
      .clearCookie("refreshToken")
      .json({ message: "Logout successful" });
  } catch (e: any) {
    return res.status(500).json({ message: e.message });
  }
};

const sendOtpMobile = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { phone } = TempSessionSchema.pick({ phone: true }).parse(req.body);
  try {
    const existigSession = await prisma.tempSession.findFirst({
      where: {
        phone,
      },
    });
    if (existigSession && existigSession.verified) {
      return res.status(400).json({ message: "User already exists" });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const result = await sendOtp(phone, otp);
    console.log("resultttttttttttttt", result);
    if (!result) {
      return res.status(400).json({ message: "Failed to send OTP" });
    } else {
      if (!existigSession) {
        await prisma.tempSession.create({
          data: {
            phone,
            otp,
            otpExpires: new Date(Date.now() + 1000 * 60 * 5),
          },
        });
      } else {
        await prisma.tempSession.update({
          where: { id: existigSession.id },
          data: {
            otp,
            otpExpires: new Date(Date.now() + 1000 * 60 * 5),
          },
        });
      }
    }
    return res
      .status(200)
      .json({ message: "OTP sent successfully", success: true });
  } catch (e: any) {
    if (e instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation failed", errors: e.errors });
    }
    return res.status(500).json({ message: e.message });
  }
};

const verifyOtpMobile = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { phone, otp } = TempSessionSchema.pick({
    phone: true,
    otp: true,
  }).parse(req.body);
  try {
    const existigSession = await prisma.tempSession.findFirst({
      where: {
        phone,
        verified: false,
      },
    });
    if (!existigSession) {
      return res.status(400).json({ message: "Invalid or already used OTP" });
    }
    const isOtpValid = existigSession.otp === otp;
    console.log("isOtpValid", isOtpValid);
    if (!isOtpValid) {
      return res.status(400).json({ message: "Invalid OTP" });
    }
    await prisma.tempSession.update({
      where: { id: existigSession.id },
      data: { verified: true },
    });
    return res
      .status(200)
      .json({ message: "OTP verified successfully", success: true });
  } catch (e: any) {
    if (e instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation failed", errors: e.errors });
    }
    return res.status(500).json({ message: e.message });
  }
};

export {
  userRegistration,
  userLogin,
  refreshUser,
  verifyUser,
  logoutUser,
  verifyUserOtp,
  sendOtpMobile,
  verifyOtpMobile,
};
