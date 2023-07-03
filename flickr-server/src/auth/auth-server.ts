import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";
import * as jwt from "jsonwebtoken";
import { User } from "../models/user";
dotenv.config();

const app: Express = express();
const port = process.env.AUTH_PORT;

app.use(express.json());

let refreshTokens: string[] = [];

app.post('/token', (req, res) => {
    const refreshToken: string = req.body.token as string;
    if (refreshToken == null) return res.sendStatus(401);
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET as string, (err, user) => {
        if (err) return res.sendStatus(403);
        let tempUser: User = (user as User);
        let resUser: User = new User(tempUser.username, tempUser.password);
        const accessToken: string = generateAccessToken(resUser)
        res.json({ accessToken: accessToken })
    })
})

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

app.post("/login", (req: Request, res: Response) => {
    const username = req.body.username;
    const password = req.body.password;

    const user: User = new User(username, password);
    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign({ user }, process.env.REFRESH_TOKEN_SECRET as string);
    refreshTokens.push(refreshToken);
    res.json({
        accessToken: accessToken,
        refreshToken: refreshToken
    });
});

function generateAccessToken(user: User) {
    let token: string = process.env.ACCESS_TOKEN_SECRET as string;
    let options = {
        expiresIn: process.env.TOKEN_EXPIRATION
    };
    return jwt.sign({ user }, token, options);
}


app.listen(port, () => {
    console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});
