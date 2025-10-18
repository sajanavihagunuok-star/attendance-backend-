module.exports = function(app){
  app.use((req,res,next)=>{
    console.log("[CORS-DEBUG] Request:", req.method, req.path);
    // after response finishes, log the headers that were sent
    const _end = res.end;
    res.end = function(...args){
      console.log("[CORS-DEBUG] Response headers:", JSON.stringify(res.getHeaders()));
      return _end.apply(this, args);
    };
    next();
  });
};
