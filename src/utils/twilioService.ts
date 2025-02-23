import twilio from "twilio";

// * ✅ CREATE TWILIO CLIENT
const client = twilio(
	process.env.TWILIO_ACCOUNT_SID,
	process.env.TWILIO_AUTH_TOKEN
);

// * ✅ SEND OTP
export const sendTOTP = async (phoneNumber: string) => {
	try {
		// * ✅ SEND OTP
		await client.verify.v2
			.services(process.env.TWILIO_VERIFY_SERVICE_SID!)
			.verifications.create({ to: phoneNumber, channel: "sms" });

		// * ✅ RETURN SUCCESS
		return { success: true, message: "OTP sent successfully" };
	} catch (error) {
		// * ✅ RETURN FAILURE
		return { success: false, message: "Failed to send OTP" };
	}
};

// * ✅ VERIFY OTP
export const verifyTOTP = async (phoneNumber: string, otpCode: string) => {
	try {
		// * ✅ VERIFY OTP
		const response = await client.verify.v2
			.services(process.env.TWILIO_VERIFY_SERVICE_SID!)
			.verificationChecks.create({ to: phoneNumber, code: otpCode });

		// * ✅ RETURN SUCCESS
		return { success: response.valid, message: response.status };
	} catch (error) {
		// * ✅ RETURN FAILURE
		return { success: false, message: "Failed to verify OTP" };
	}
};
