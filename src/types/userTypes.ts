import { z } from "zod";

export const AddressSchema = z.object({
  line1: z.string().min(1),
  line2: z.string().optional(),
  city: z.string().min(1),
  state: z.string().min(1),
  pin: z.string().min(4).max(6),
  isPermanent: z.boolean().optional(),
  isActive: z.boolean().optional(),
});

export const TempSessionSchema = z.object({
  email: z.string().email(),
  phone: z.string().min(10),
  otp: z.string().min(6).max(6),
  verified: z.boolean().optional(),
  otpExpires: z.date(),
});

export const RegisterUserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  password: z.string().min(6),
  phone: z.string().min(10),
  dob: z.string().refine(
    (val) => {
      const date = new Date(val);
      return !isNaN(date.getTime());
    },
    {
      message: "Invalid date format. Must be a valid ISO date string.",
    }
  ),
  profilePic: z.string().url().optional(),
  address: z.union([AddressSchema, z.array(AddressSchema)]),
});
