const cors = require("cors");

module.exports = function(app){
  const allowlist = new Set([
    "https://www.mentorbridge.lk",
    "https://mentorbridge.lk"
  ]);

  const corsOptions = {
    origin: function(origin, callback) {
      // allow requests with no origin (e.g., server-to-server or curl)
      if (!origin) return callback(null, true);
      if (allowlist.has(origin)) {
        return callback(null, true);
      } else {
        return callback(new Error("Not allowed by CORS"));
      }
    },
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS",
    allowedHeaders: ["Content-Type","Authorization","X-Requested-With","Accept"],
    credentials: true,
    optionsSuccessStatus: 204
  };

  app.use((req, res, next) => {
    // Ensure preflight is fast: handle OPTIONS early
    if (req.method === "OPTIONS") {
      // cors middleware will set the proper Access-Control-* headers
      return cors(corsOptions)(req, res, () => res.status(204).end());
    }
    next();
  });

  // Apply CORS to non-OPTIONS requests
  app.use(cors(corsOptions));

  // Safe fallback header setter (only for diagnostics; harmless if proper headers exist)
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && allowlist.has(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept");
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
    next();
  });
};
