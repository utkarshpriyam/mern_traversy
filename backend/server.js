const express = require('express')
const colors =  require('colors')
const dotenv = require('dotenv').config()
const connectDB = require('./config/db')
// allows to have dotenv  file with variables 
const {errorHandler} = require('./middleware/errorMiddleware')

connectDB()

const port=process.env.PORT || 5000;
const app=express()

app.use(express.json())
app.use(express.urlencoded({extended: false}))

app.use('/api/goals', require('./routes/goalRoutes'));

app.use(errorHandler)
app.listen(port, () => console.log(`Server started on port ${port}`))