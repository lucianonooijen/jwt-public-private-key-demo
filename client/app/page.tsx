"use client"

import {removeJwtCookie} from "@/data/jwt/cookiesClient";
import {useRouter} from "next/navigation";

export default function Home() {
    const router = useRouter()
    const logout = () => {
        removeJwtCookie();

        setTimeout(router.refresh, 500)
    }

    return (
          <div>
              <p>Hello, world!</p>
              <button onClick={logout}>Logout</button>
          </div>
    );
}
