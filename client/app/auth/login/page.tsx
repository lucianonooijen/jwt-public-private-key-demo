"use client";

import {setJwtCookie} from "@/data/jwt/cookiesClient";
import {useRouter} from "next/navigation";

export default function LoginPage() {
    const router = useRouter();
    const login = () => {
        fetch('http://localhost:4000/jwt')
            .then(res => res.json())
            .then(res => {
                const jwt = res.token
                const expiry = res.expiry
                console.log("jwt: ", jwt, " expiry ", expiry)

                setJwtCookie(jwt, expiry)

                setTimeout(router.refresh, 500)
            })
    }

    return (
        <div>
            <p>Login page</p>
            <button onClick={login}>Login</button>
        </div>
    );
}
