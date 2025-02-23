import { User } from "@prisma/client";
import { readFile } from "fs/promises";
import { Resend } from "resend";

// * ✅ CREATE RESEND INSTANCE
const resend = new Resend(process.env.RESEND_API_KEY);

// * ✅ EMAIL SERVICE
export default class EmailService {
	// * ✅ CONSTRUCTOR
	constructor(private user: User) {}

	// * ✅ SEND EMAIL
	async sendEmail(template: string, subject: string) {
		return await resend.emails.send({
			from: "ChatWithMe <onboarding@resend.dev>",
			to: this.user.email,
			subject: subject,
			html: template,
		});
	}

	// * ✅ SEND WELCOME EMAIL
	async sendWelcome(url: string) {
		const template = (
			await readFile(`${process.cwd()}/src/templates/welcome.html`, "utf-8")
		)
			.replace("[UserName]", this.user.name)
			.replace("[Link]", url);
		return this.sendEmail(template, "Welcome to ChatWithMe!");
	}

	// * ✅ SEND RESET PASSWORD
	async sendResetPassword(url: string) {
		const template = (
			await readFile(
				`${process.cwd()}/src/templates/resetPassword.html`,
				"utf-8"
			)
		)
			.replace("[UserName]", this.user.name)
			.replace("[Link]", url);

		return this.sendEmail(template, "Password Reset Request");
	}

	// * ✅ SEND SECURITY CODE
	async sendSecurityCode(code: string) {
		const template = (
			await readFile(
				`${process.cwd()}/src/templates/securityCode.html`,
				"utf-8"
			)
		)
			.replace("[User]", this.user.name)
			.replace("[Code]", code);

		return this.sendEmail(template, "Verification Security Code");
	}
}
