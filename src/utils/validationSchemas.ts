import { z } from "zod";

export const userSchema = z.object({
	name: z
		.string({ required_error: "Name is required" })
		.min(3, { message: "Name must be at least 3 characters long" })
		.max(30, { message: "Name must be at most 30 characters long" }),

	email: z
		.string({ required_error: "Email is required" })
		.email({ message: "Invalid email address" }),

	photo: z
		.string({ required_error: "Photo is required" })
		.url({ message: "Invalid URL for photo" }),

	password: z
		.string({ required_error: "Password is required" })
		.min(8, { message: "Password must be at least 8 characters" })
		.max(100, { message: "Password must not exceed 100 characters" })
		.regex(/[A-Z]/, {
			message: "Password must contain at least one uppercase letter (A-Z)",
		})
		.regex(/[a-z]/, {
			message: "Password must contain at least one lowercase letter (a-z)",
		})
		.regex(/[0-9]/, {
			message: "Password must contain at least one number (0-9)",
		})
		.regex(/[\W_]/, {
			message:
				"Password must contain at least one special character (!@#$%^&*)",
		}),

	phoneNumber: z
		.string({ required_error: "Phone number is required" })
		.min(10, { message: "Phone number must be at least 10 digits" })
		.max(15, { message: "Phone number must not exceed 15 digits" })
		.regex(/^\+?[0-9]+$/, {
			message: "Phone number must start with a + and contain only numbers",
		}),
});
