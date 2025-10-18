module.exports = function(app){
  const allowlist = new Set([
    "https://www.mentorbridge.lk",
    "https://mentorbridge.lk"
  ]);

  // Explicit preflight handler placed as early as possible
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (req.method === "OPTIONS") {
      if (origin && allowlist.has(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", req.headers["access-control-request-headers"] || "Content-Type, Authorization, X-Requested-With, Accept");
        res.setHeader("Access-Control-Allow-Credentials", "true");
        // Avoid cache by proxies for OPTIONS
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0");
        return res.status(204).end();
      } else {
        return res.status(204).end();
      }
    }
    next();
  });

  // For other requests, echo origin when allowed
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && allowlist.has(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
    next();
  });
};
