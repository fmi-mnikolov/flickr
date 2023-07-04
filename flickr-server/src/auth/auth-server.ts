import dotenv from 'dotenv';
import express, { Express, Request, Response } from "express";
import * as jwt from "jsonwebtoken";
import { User } from "../models/user";
import * as redis from "redis";
dotenv.config();


const app: Express = express();
const port = process.env.AUTH_PORT;

const redisClient = redis.createClient({
    url: `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`
});
redisClient.connect();



app.use(express.json());

app.post('/token', (req, res) => {
    let token = req.body.token;
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET as string, (err, user) => {
        if (err) return res.sendStatus(403);
        let tempUser: { user: User } = user;
        let resUser: User = new User(tempUser.user.username, tempUser.user.password);
        redisClient.GET(resUser.username).then(dbtoken => {
            if (token !== dbtoken) return res.sendStatus(403);
            const accessToken: string = generateAccessToken(resUser)
            res.json({ accessToken: accessToken })
        }).catch(err => {
            return res.sendStatus(403);
        })
    })
})

app.delete('/logout', (req, res) => {
    let token = req.body.token;
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET as string, (err, user) => {
        if (err) return res.sendStatus(403);
        let tempUser: { user: User } = user;
        let resUser: User = new User(tempUser.user.username, tempUser.user.password);
        redisClient.GET(resUser.username).then(dbtoken => {
            if (token !== dbtoken) return res.sendStatus(403);
            redisClient.DEL(resUser.username);
            return res.sendStatus(204);
        })
    })
})

app.post("/login", (req: Request, res: Response) => {
    const username = req.body.username;
    const password = req.body.password;

    const user: User = new User(username, password);
    const accessToken = generateAccessToken(user);
    let refreshToken = jwt.sign({ user }, process.env.REFRESH_TOKEN_SECRET as string);
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
