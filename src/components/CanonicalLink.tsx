import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { SITE_ORIGIN } from "../lib/site";

/**
 * The SPA ships one index.html, so the static canonical only fits "/".
 * Keep the tag in step with the current route so deep links do not all
 * claim the home page as their canonical.
 */
export function CanonicalLink() {
  const { pathname } = useLocation();

  useEffect(() => {
    let link = document.head.querySelector<HTMLLinkElement>(
      'link[rel="canonical"]',
    );
    if (!link) {
      link = document.createElement("link");
      link.rel = "canonical";
      document.head.appendChild(link);
    }
    link.href = `${SITE_ORIGIN}${pathname}`;
  }, [pathname]);

  return null;
}
