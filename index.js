const express = require("express");
const cors = require("cors");
const { errorHandler } = require("./middlewares/error");
require("dotenv").config();
require("./db");
const userRouter = require("./routers/user");
const { handleNotFound } = require("./utils/helper");




const app = express()
app.use(express.json());
app.use(cors());
app.use("/api/user",userRouter);


app.listen(8000, () => { 
    console.log("port is active at 8000  ")
})
