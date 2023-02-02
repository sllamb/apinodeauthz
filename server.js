const express = require('express');
const cors = require('cors');
const { join } = require("path");
const helmet = require("helmet");
const nocache = require("nocache");

const { auth, claimIncludes, claimCheck, requiredScopes } = require('express-oauth2-jwt-bearer');

const app = express();
app.use(cors({
  origin: 'http://localhost:3000'
}));
app.use('/*', express.static('public'));
app.use(helmet());
app.use(nocache());

app.get('/api/public', (req, res) => {
    res.json({
      message: 'this is a public endpoint that does NOT require authentication'
    });
  });

  app.get("/auth_config.json", (req, res) => {
    res.sendFile(join(__dirname, "auth_config.json"));
  });

  app.get("/", (req, res) => {
    res.sendFile(join(__dirname, "index.html"));
  });

  //ENDPOINTS BELOW ARE AUTHENTICATED
  require('dotenv').config();
  const {
      ISSUER_BASE_URL,
      AUDIENCE,
      PORT = 8080,
    } = process.env;
    console.log("\n----------------------------------");
    console.log("Envronment Settings:");
    //console.log(`APP_URL: ${appUrl}`);
    console.log(`ISSUER_BASE_URL: ${ISSUER_BASE_URL}`);
    console.log(`AUDIENCE: ${AUDIENCE}`);
    console.log("----------------------------------\n");
    
app.use(auth());
app.get('/api/authn', (req, res) => {
    res.json({
      message: 'Success, you are authenticated.  No Authorization was performed on this endpoint - only authentication.'
    });
  });

app.get('/api/authz-role-check', claimCheck((claims) => {
    console.log("roles claim " + claims.custom_roles)
    return claims['https://cic-slamb/roles'].includes('reportAdmin');
  }, `Missing roleAdmin`), (req, res) => {
    res.json({
      message: 'Success, You are authenticated & authorized based on having the role claim with a value of roleAdmin'
    });
  });


app.get('/api/authz-scope-check', requiredScopes('read:reports'), (req, res) => {
  res.json({
    message: 'Success, You are authenticated and have a scope of read:reports'
  });
});

  app.use(function(err, req, res, next) {
    if (err.name === "UnauthorizedError") {
      return res.status(401).send({ msg: "Invalid token!" });
    } else if (err.name === "InsufficientScopeError") {
        return res.status(403).send({ msg: "Insufficient Permissions to call this endpoint" });
    }
  
    next(err, req, res);
  });
  
  process.on("SIGINT", function() {
    process.exit();
  });
 
  module.exports = app;
