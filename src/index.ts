import express from  'express';
import http from 'http';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';

import router from './router';

const app=express();

app.use(cors({
    credentials: true,
}));

app.use(compression());
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}));

const server= http.createServer(app);

server.listen(8080, ()=>{
   console.log("server running on http://localhost:8080/"); 
});

dotenv.config();

mongoose.Promise=Promise;
mongoose.connect(process.env.MONGO_URI);

mongoose.connection.on("error", (error: Error) => console.log(error));

app.use("/",router());