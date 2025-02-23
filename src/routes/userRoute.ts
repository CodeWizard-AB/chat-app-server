import { Router } from "express";
import {
	forgotPassword,
	login,
	logout,
	resetPassword,
	signup,
	updatePassword,
	verifyOtp,
	verifyToken,
} from "../controllers/authController.ts";

// * ✅ CREATE ROUTER
const router = Router();

// * ✅ PUBLIC ROUTES
router.post("/signup", signup);
router.post("/login", login);
router.get("/logout", logout);
router.post("/forgotPassword", forgotPassword);
router.post("/verifyOtp", verifyOtp);
router.patch("/resetPassword/:token", resetPassword);

// * ✅ PROTECTED ROUTES
router.use(verifyToken);

router.patch("/updatePassword", updatePassword);

export default router;
