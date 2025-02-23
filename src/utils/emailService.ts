import { User } from "@prisma/client";
import { readFile } from "fs/promises";
import { Resend } from "resend";

// * ✅ CREATE RESEND INSTANCE
const resend = new Resend(process.env.RESEND_API_KEY);

// * ✅ EMAIL SERVICE
export default class EmailService {
	// * ✅ CONSTRUCTOR
	constructor(private user: User, private url: string) {}

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
	async sendWelcome() {
		const template = (
			await readFile(`${process.cwd()}/src/templates/welcome.html`, "utf-8")
		)
			.replace("[UserName]", this.user.name)
			.replace("[Link]", this.url);
		return this.sendEmail(template, "Welcome to ChatWithMe!");
	}

	// * ✅ SEND RESET PASSWORD
	async sendResetPassword() {
		const template = (
			await readFile(
				`${process.cwd()}/src/templates/resetPassword.html`,
				"utf-8"
			)
		)
			.replace("[UserName]", this.user.name)
			.replace("[Link]", this.url);
		return this.sendEmail(template, "Password Reset Request");
	}
}
