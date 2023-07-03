import { Request } from "express";

export interface APIRequest extends Request {
    user?: string;
}