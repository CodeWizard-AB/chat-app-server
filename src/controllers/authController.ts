import "dotenv/config";
import jwt from "jsonwebtoken";
import catchAsync from "../utils/catchAsync.ts";
import { NextFunction, Request, Response } from "express";
import prisma from "../utils/prisma.ts";
import { userSchema } from "../utils/validationSchemas.ts";
import createHttpError from "http-errors";
import bcrypt from "bcrypt";

const signToken = (id: string) => {
	return jwt.sign({ id }, process.env.JWT_ACCESS_SECRET!, {
		expiresIn: "15m",
	});
};

const verifyToken = () => {};
const createAccessToken = () => {};
const createRefeshToken = () => {};
const createHashPassword = () => {};

export const signup = catchAsync(
	async (req: Request, res: Response, next: NextFunction) => {
		// * ✅ Step 1: Validate Request Body
		const validation = userSchema.safeParse(req.body);

		if (!validation.success) {
			const errors = validation.error.errors.map((err) => ({
				field: err.path.join("."),
				message: err.message,
			}));

			return next(
				createHttpError(400, {
					message: "Validation failed",
					errors,
				})
			);
		}

		const { email, phoneNumber, password } = validation.data;

		// * ✅ Step 2: Check If User Exists
		const existingUser = await prisma.user.findUnique({
			where: { email },
		});

		if (existingUser) return next(createHttpError(409, "User already exists"));

		const newUser = await prisma.user.create({
			data: validation.data,
		});

		// const result = await axios(
		// 	`${process.env.ABSTRACT_API_URL}?api_key=${process.env.ABSTRACT_API_KEY}&email=${validation.data.email}`
		// );

		// console.log(result);

		// ✅ Step 5: Hash Password Before Saving
		const hashedPassword = await bcrypt.hash(password, 12);

		res.json(newUser);
	}
);

export const login = () => {};
export const logout = () => {};
export const protect = () => {};
export const retrictTo = () => {};
export const forgotPassword = () => {};
export const resetPassword = () => {};
export const updatePassword = () => {};
