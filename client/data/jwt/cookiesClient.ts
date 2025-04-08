"use client";

import {JwtData, jwtStorageKey} from "@/data/jwt/jwtData";
import Cookies from "js-cookie";

export const setJwtCookie = (token: string, expiry: string) => {
    Cookies.set(jwtStorageKey, token, {
        expires: new Date(expiry*1000),
        secure: true,
        sameSite: "Strict",
        httpOnly: false,
    });
};

export const removeJwtCookie = () => {
    Cookies.remove(jwtStorageKey);
};
