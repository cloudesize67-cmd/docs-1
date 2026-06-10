import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { allPages } from "content-collections";

const pageUrlSet = new Set(allPages.map(page => page.url));

// Matches /guides/<slug> — one path segment, no deeper nesting.
// Avoids importing allGuides (and its compiled MDX bodies) into the Edge bundle.
const guidePathRe = /^\/guides\/[^/]+$/;

function prefersMarkdown(acceptHeader: string): boolean {
  const types = acceptHeader.split(",");
  const mdIdx = types.findIndex(t => t.includes("text/markdown") || t.includes("text/plain"));
  const htmlIdx = types.findIndex(t => t.includes("text/html"));
  return mdIdx !== -1 && (htmlIdx === -1 || mdIdx < htmlIdx);
}

export function middleware(request: NextRequest) {
  const { pathname, searchParams } = request.nextUrl;

  if (pathname.startsWith("/api/")) {
    return NextResponse.next();
  }

  const hasMdExtension = pathname.endsWith(".md");
  const pagePath = hasMdExtension ? pathname.slice(0, -3) : pathname;

  const isPage = pageUrlSet.has(pagePath);
  const isGuide = !isPage && guidePathRe.test(pagePath);

  if (!isPage && !isGuide) {
    return NextResponse.next();
  }

  const wantsMarkdown =
    hasMdExtension ||
    searchParams.get("format") === "md" ||
    prefersMarkdown(request.headers.get("accept") || "");

  // For guides, only intercept when markdown is requested — normal guide requests
  // are handled by pages/guides/[...slug].tsx via the default Next.js routing.
  // If the slug doesn't match a real guide the dynamic handler returns 404.
  if (isGuide && !wantsMarkdown) {
    return NextResponse.next();
  }

  const url = request.nextUrl.clone();
  url.pathname = "/dynamic" + pagePath;
  if (wantsMarkdown) {
    url.searchParams.set("format", "md");
  }
  return NextResponse.rewrite(url);
}

export const config = {
  matcher: "/:path*",
};
