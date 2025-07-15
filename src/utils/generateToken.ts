import jwt from "jsonwebtoken";

const getJwtSecret = (): string => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is not defined in environment variables");
  }
  return secret;
};

const generateToken = (id: string | number, time: string) => {
  return jwt.sign({ id }, getJwtSecret(), { expiresIn: time as jwt.SignOptions["expiresIn"] });
};

export default generateToken;
