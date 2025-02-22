import "dotenv/config";
import jwt from "jsonwebtoken";
import catchAsync from "../utils/catchAsync.ts";
import { NextFunction, Request, Response } from "express";
import prisma from "../utils/prisma.ts";
import { userSchema } from "../utils/validationSchemas.ts";
import createHttpError from "http-errors";
import bcrypt from "bcrypt";
import { verifyEmail, verifyPhone } from "../utils/verificationServices.ts";
import { User } from "@prisma/client";

// * ✅ SIGN TOKEN
const signToken = (id: string, secret: string, expiresIn: number) => {
	return jwt.sign({ id }, secret, { expiresIn: expiresIn });
};

// * ✅ VERIFY TOKEN
const verifyToken = () => {};

// * ✅ SET COOKIE
const setCookie = (
	name: string,
	token: string,
	expiry: number,
	req: Request,
	res: Response
) => {
	res.cookie(name, token, {
		expires: new Date(Date.now() + expiry),
		httpOnly: true,
		secure: req.secure || req.headers["x-forwarded-proto"] === "https",
		sameSite: "none",
	});
};

// * ✅ CREATE ACCESS AND REFRESH TOKEN
const createSendTokens = (
	user: User,
	statusCode: number,
	req: Request,
	res: Response
) => {
	// * ✅ CREATE ACCESS AND REFRESH TOKEN
	const accessToken = signToken(
		user.id,
		process.env.JWT_ACCESS_SECRET!,
		+process.env.JWT_ACCESS_TOKEN_EXPIRY! * 60 * 1000
	);
	const refreshToken = signToken(
		user.id,
		process.env.JWT_REFRESH_SECRET!,
		+process.env.JWT_REFRESH_TOKEN_EXPIRY! * 24 * 60 * 60 * 1000
	);

	// * ✅ REMOVE PASSWORD FROM USER OBJECT
	const { password, ...rest } = user;

	// * ✅ SET COOKIES
	setCookie(
		"accessToken",
		accessToken,
		+process.env.JWT_ACCESS_TOKEN_EXPIRY! * 60 * 1000,
		req,
		res
	);
	setCookie(
		"refreshToken",
		refreshToken,
		+process.env.JWT_REFRESH_TOKEN_EXPIRY! * 60 * 60 * 1000 * 24,
		req,
		res
	);

	// * ✅ SEND RESPONSE
	res.status(statusCode).json({
		status: "success",
		data: { user: rest },
		token: accessToken,
	});
};

// * ✅ SIGNUP
export const signup = catchAsync(
	async (req: Request, res: Response, next: NextFunction) => {
		// * ✅ STEP 1: VALIDATE REQUEST BODY
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

		// * ✅ STEP 2: CHECK IF USER EXISTS
		const existingUser = await prisma.user.findUnique({
			where: { email },
		});
		if (existingUser) {
			return next(createHttpError(409, "User already exists"));
		}

		// * ✅ STEP 3: VERIFY EMAIL
		const emailResult = await verifyEmail(email);
		if (!emailResult.success) {
			return next(createHttpError(400, emailResult.message));
		}

		// * ✅ STEP 4: VERIFY PHONE NUMBER
		const phoneResult = await verifyPhone(phoneNumber);
		if (!phoneResult.success) {
			return next(createHttpError(400, phoneResult.message));
		}

		// * ✅ STEP 5: HASH PASSWORD
		const hashedPassword = await bcrypt.hash(password, 12);

		// * ✅ STEP 6: CREATE USER
		const newUser = await prisma.user.create({
			data: { ...validation.data, password: hashedPassword },
		});

		// * ✅ STEP 7: CREATE ACCESS AND REFRESH TOKEN
		createSendTokens(newUser, 201, req, res);
	}
);

export const login = () => {};
export const logout = () => {};
export const protect = () => {};
export const retrictTo = () => {};
export const forgotPassword = () => {};
export const resetPassword = () => {};
export const updatePassword = () => {};
