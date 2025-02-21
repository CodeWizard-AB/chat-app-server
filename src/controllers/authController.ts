import "dotenv/config";
import jwt from "jsonwebtoken";
import catchAsync from "../utils/catchAsync.ts";
import { Request, Response } from "express";
import prisma from "../utils/prisma.ts";

const signToken = (id: string) => {
	return jwt.sign({ id }, process.env.JWT_ACCESS_SECRET!, {
		expiresIn: "15m",
	});
};

const verifyToken = () => {};
const createAccessToken = () => {};
const createRefeshToken = () => {};

export const signup = catchAsync(async (req: Request, res: Response) => {
	console.log(req.body);
	res.status(201).json({ status: "success signup" });
});

export const login = () => {};
export const logout = () => {};
const protect = () => {};
const retrictTo = () => {};
const forgotPassword = () => {};
const resetPassword = () => {};
const updatePassword = () => {};
