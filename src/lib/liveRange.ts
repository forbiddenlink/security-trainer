/** The live range is localhost docker containers: only meaningful on a
 *  localhost origin. Over HTTPS (prod) an http://localhost probe is
 *  mixed-content blocked and the links would be dead. */
export const isLocalRangeAvailable =
  typeof window !== "undefined" &&
  (window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1");
