import { NextFunction, Request, Response } from "express";

// * DEVELOPMENT ERROR HANDLER
const sendErrorDev = (err: any, req: Request, res: Response) => {
	if (req.originalUrl.startsWith("/api")) {
		res.status(err.statusCode).json({
			status: err.status,
			error: err,
			message: err.message,
			stack: err.stack,
		});
	}
};

// * PRODUCTION ERROR HANDLER
const sendErrorProd = (err: any, req: Request, res: Response) => {};

// * GLOBAL ERROR HANDLER
export default (err: any, req: Request, res: Response, next: NextFunction) => {
	err.statusCode = err.statusCode || 500;
	err.status = err.status || "error";

	if (process.env.NODE_ENV === "DEVELOPMENT") {
		sendErrorDev(err, req, res);
	} else if (process.env.NODE_ENV === "PRODUCTION") {
		sendErrorProd(err, req, res);
	}
};
