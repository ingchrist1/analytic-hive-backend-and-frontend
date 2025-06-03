import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const isAuthPage = request.nextUrl.pathname.startsWith('/auth')
  const token = request.cookies.get('auth')?.value

  // Redirect to auth page if trying to access protected routes without token
  if (!token && !isAuthPage) {
    const redirectUrl = new URL('/auth', request.url)
    redirectUrl.searchParams.set('from', request.nextUrl.pathname)
    return NextResponse.redirect(redirectUrl)
  }

  // Redirect to home if trying to access auth page with token
  if (token && isAuthPage) {
    return NextResponse.redirect(new URL('/', request.url))
  }

  return NextResponse.next()
}

// Configure which routes to run middleware on
export const config = {
  matcher: [
    /*
     * Match all routes except for:
     * 1. /api routes
     * 2. /_next (Next.js internals)
     * 3. /_static (inside /public)
     * 4. /favicon.ico, /sitemap.xml (static files)
     */
    '/((?!api|_next|_static|favicon.ico|sitemap.xml).*)',
  ],
}
