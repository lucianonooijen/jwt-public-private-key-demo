import { type JwkJwt, type JwkResponse, JwkResponseSchema } from "@/data/jwt/jwk-jwt";
import * as jose from "jose";

const tokenId = "jwt-demo-server-jwk";
const algorithm = "RS256";
const jwkUri = ".well-known/jwks.json";
const expectedAudience = "example";
const expectedIssuer = "jwt-demo-server";

// Class used to cache values
// Webapp needs to be restarted if the key changes
// biome-ignore lint/complexity/noStaticOnlyClass: this is preferred
export default class JwtValidator {
    private static _jwk: JwkJwt | null = null;

    // Can throw errors
    private static async getJwk(): Promise<JwkJwt> {
        if (JwtValidator._jwk) return JwtValidator._jwk;

        const jwkEndpoint = `http://localhost:4000/${jwkUri}`; // Change this
        console.log("jwkEndpoint", jwkEndpoint);

        // Load and process jwk, find the key we need
        const jwkRes = await fetch(jwkEndpoint);
        const jwkResJson = await jwkRes.json();
        const jwkResJsonParsed = JwkResponseSchema.parse(jwkResJson);
        const jwks: JwkResponse["keys"] = jwkResJsonParsed.keys;
        const jwk = jwks.find(j => j.kid === tokenId);
        if (!jwk) {
            console.error("jwk not found with key", tokenId);
            throw new Error("jwk not found");
        }

        JwtValidator._jwk = jwk;
        return jwk;
    }

    public static async ValidateJwt(jwt: string): Promise<boolean> {
        const jwk = await JwtValidator.getJwk();

        try {
            // Throws if validation fails
            await jose.importJWK(jwk, algorithm);
            const validated = await jose.jwtVerify(jwt, jwk, {
                algorithms: [algorithm],
                audience: expectedAudience,
                issuer: expectedIssuer,
            });

            // Sanity check
            return validated.payload.iss === expectedIssuer && validated.payload.aud === expectedAudience;
        } catch (e) {
            console.warn("decoding jwt failed", e);
            return false;
        }
    }
}
