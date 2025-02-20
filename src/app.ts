import express, { NextFunction, Request, Response } from "express";
import createHttpError from "http-errors";
import globalErrorHandler from "./controllers/errorController.ts";
import cookieParser from "cookie-parser";

// * CREATE EXPRESS APP
const app = express();

// * MIDDLEWARES
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// * ALL ROUTES
app.get("/api", (req, res) => {
	res.send("Hello World!");
});

// * 404 ERROR HANDLER
app.use((req: Request, _res: Response, next: NextFunction) => {
	next(createHttpError(404, `Can't find ${req.originalUrl} on this server!`));
});

// * ERROR HANDLER
app.use(globalErrorHandler);

export default app;
