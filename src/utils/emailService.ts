import { User } from "@prisma/client";
import { readFile } from "fs/promises";
import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);

export default class EmailService {
	constructor(private user: User) {}
	async sendEmail(template: string, subject: string) {
		return await resend.emails.send({
			from: "ChatWithMe <onboarding@resend.dev>",
			to: this.user.email,
			subject: subject,
			html: template,
		});
	}

	async sendWelcome() {
		const template = (
			await readFile(
				`${process.cwd()}/src/templates/welcome.html`,
				"utf-8"
			)
		).replace("[UserName]", this.user.name);
		return this.sendEmail(template, "Welcome to ChatWithMe!");
	}

	async sendResetPassword() {}
}
