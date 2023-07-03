import express, { Express, NextFunction, Request, Response } from "express";
import dotenv from "dotenv";
import * as jwt from "jsonwebtoken";
import { User } from "./models/user";
import { APIRequest } from "./models/request";
dotenv.config();

const app: Express = express();
const port = process.env.PORT;
const authenticate = (req: APIRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET as string, (err, user) => {
        console.log(err);
        if (err) return res.sendStatus(403);
        req.user = user as string;
        next();
    })
}

app.use(express.json());

app.get("/", authenticate, (req: APIRequest, res: Response) => {
    return res.json(req.user);
})

app.listen(port, () => {
    console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});