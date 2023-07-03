import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";
import * as jwt from "jsonwebtoken";
import { User } from "../models/user";
import { createClient } from "redis";
dotenv.config();


const app: Express = express();
const port = process.env.AUTH_PORT;

const redisClient = createClient({
    url: `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`,
    password: process.env.REDIS_PASS
});

app.use(express.json());

let refreshTokens: string[] = [];

app.post('/token', (req, res) => {
    const refreshToken: string = req.body.token as string;
    if (refreshToken == null) return res.sendStatus(401);

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET as string, (err, user) => {
        if (err) return res.sendStatus(403);
        let tempUser: User = (user as User);
        let resUser: User = new User(tempUser.username, tempUser.password);
        redisClient.get(resUser.username).then(token => {
            const accessToken: string = generateAccessToken(resUser)
            res.json({ accessToken: accessToken })
        }).catch(err => {
            console.log(err);
            return res.sendStatus(403);
        });
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
    redisClient.setEx(username, 2 * 60 * 60, refreshToken);
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
