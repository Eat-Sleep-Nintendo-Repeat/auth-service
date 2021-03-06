const express = require("express");
var bodyParser = require('body-parser')
var cookieParser = require("cookie-parser");


const app = express();
app.use(cookieParser());
app.use(bodyParser.json())

app.use((req, res, next) => {
    res.setHeader("x-esnr-microservice-id", "auth")
    next();
})

//database
require("./database")

//import routes
app.use("/", require("./routes/index"))

app.listen(7872, () => {
    console.log("AUTH_SERVICE is active and listenig on 7872");
})