const cors = require("cors");

module.exports = function(app){
  const corsOptions = {
    origin: ["https://www.mentorbridge.lk","https://mentorbridge.lk"],
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS",
    allowedHeaders: ["Content-Type","Authorization","X-Requested-With","Accept"],
    credentials: true,
    optionsSuccessStatus: 204
  };

  // apply CORS middleware for all routes and preflight
  app.use(cors(corsOptions));
  app.options("*", cors(corsOptions));

  // fallback headers in case something strips the automatic headers
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "https://www.mentorbridge.lk");
    res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    next();
  });
};
