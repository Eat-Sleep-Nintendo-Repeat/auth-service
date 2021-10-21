const express = require("express");

const routes = express.Router();

routes.use("/discord", require("./auth/gain_access"))

module.exports = routes;
