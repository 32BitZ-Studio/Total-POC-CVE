import { NextResponse } from "next/server";

export function middleware(req) {
  const authHeader = req.headers.get("authorization");

  if (!authHeader || authHeader !== "my-jwt-token-here") {
    return NextResponse.json(
      {
        error: "Unauthorized",
      },
      { status: 401 }
    );
  }

  return NextResponse.next();
}

// Apply middleware to all API routes
export const config = {
  matcher: "/api/:path*",
};
