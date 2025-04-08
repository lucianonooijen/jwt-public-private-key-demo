import { z } from "zod";

export const jwtStorageKey = "jwk-demo-server-jwt-v1";

export const JwtDataSchema = z.object({
    token: z.string(),
    firstName: z.string(),
    lastName: z.string(),
    email: z.string(),
    userUUID: z.string(),
    tokenExpiry: z.string(),
    role: z.enum(["Admin", "User"]),
});

export type JwtData = z.infer<typeof JwtDataSchema>;
