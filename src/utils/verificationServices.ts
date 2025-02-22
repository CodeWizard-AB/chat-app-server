import axios from "axios";

//* ✅ VERIFY EMAIL
export const verifyEmail = async (email: string) => {
	try {
		// * ✅ CALL ABSTRACT API FOR EMAIL VERIFICATION
		const { data } = await axios(
			`${process.env.ABSTRACT_EMAIL_API_URL}?api_key=${process.env.ABSTRACT_EMAIL_API_KEY}&email=${email}`
		);

		// * 🛑 1. INVALID FORMAT (BASIC STRUCTURE CHECK)
		if (!data.is_valid_format.value) {
			return { success: false, message: "Invalid email format" };
		}

		// * 🛑 2. TYPO CORRECTION SUGGESTION
		if (data.autocorrect) {
			return {
				success: false,
				message: `Did you mean '${data.autocorrect}'? The email might be misspelled.`,
			};
		}

		// * 🛑 3. UNDELIVERABLE EMAIL (IF IT CAN'T RECEIVE MESSAGES)
		if (data.deliverability !== "DELIVERABLE") {
			return { success: false, message: "Email address is undeliverable." };
		}

		// * 🛑 4. DISPOSABLE EMAIL CHECK (TEMPORARY EMAIL PROVIDERS)
		if (data.is_disposable_email.value) {
			return { success: false, message: "Disposable emails are not allowed." };
		}

		// * 🛑 5. ROLE-BASED EMAIL CHECK (ADMIN@, SUPPORT@, ETC.)
		if (data.is_role_email.value) {
			return { success: false, message: "Role-based emails are not allowed." };
		}

		// * 🛑 6. CATCH-ALL EMAIL CHECK (ACCEPTS ALL MESSAGES, COULD BE FAKE)
		if (data.is_catchall_email.value) {
			return { success: false, message: "Catch-all emails are not accepted." };
		}

		// * 🛑 7. SMTP CHECK (VERIFIES IF THE EMAIL EXISTS ON THE SERVER)
		if (!data.is_smtp_valid.value) {
			return {
				success: false,
				message: "Email does not exist on the mail server.",
			};
		}

		// * ✅ IF ALL CHECKS PASS, EMAIL IS VALID!
		return { success: true, message: "Email is valid and deliverable." };
	} catch (error) {
		// * 🛑 IF THERE'S AN ERROR, RETURN FALSE
		return { success: false, message: "Email verification failed" };
	}
};

// * ✅ VERIFY PHONE
export const verifyPhone = async (phone: string) => {
	try {
		// * ✅ CALL ABSTRACT API FOR PHONE VERIFICATION
		const { data } = await axios(
			`${process.env.ABSTRACT_PHONE_API_URL}?api_key=${process.env.ABSTRACT_PHONE_API_KEY}&phone=${phone}`
		);

		// * 🛑 1. INVALID FORMAT
		if (!data.valid) {
			return { success: false, message: "Invalid phone number." };
		}

		// * 🛑 2. INVALID DEVICE
		if (data.type !== "mobile")
			return { success: false, message: "Only mobile numbers are allowed." };

		// * ✅ IF ALL CHECKS PASS, PHONE NUMBER IS VALID
		return { success: true, message: "Valid phone number" };
	} catch (error) {
		// * 🛑 IF THERE'S AN ERROR, RETURN FALSE
		return { success: false, message: "Phone verification failed." };
	}
};
