import express, {Request, Response} from 'express';

import { getUserByEmail, createUser } from '../db/users';
import { random, authentication } from '../helpers';

export const login = async(req: Request,res: Response)=>{
    try{
        const {email,password}=req.body;

        if(!email ||!password){
            return res.status(400).json({
                status: 'error',
                message: 'Please provide both email and password to login'
            });
        }
        const user=await getUserByEmail(email).select('+authentication.salt +authentication.password');

        if(!user){
            return res.status(400).json({
                status: 'error',
                message: 'Unable to find user with the following credentials'
            });
        }

        const expectedHash=authentication(user.authentication.salt, password);

        if(user.authentication.password !== expectedHash){
            return res.status(403).json({
                status: 'error',
                message: 'Please provide correct password'
            });
        }

        const salt=random();
        user.authentication.sessionToken=authentication(salt,user._id.toString());

        await user.save();

        res.cookie('APPLICATION-AUTH',user.authentication.sessionToken,{domain: 'localhost', path: '/'});
        
        return res.status(200).json(user).end();
    }catch(error){
        console.log(error);
        return res.sendStatus(400);
    }
};

export const register= async(req: Request, res: Response)=>{
    try{
        const {email, password, username} =req.body;

        if(!email || !password || !username){
            return res.status(400).json({
                status: 'error',
                message: 'Please provide all the required parameters.'
            });
        }

        const existingUser=await getUserByEmail(email);

        if(existingUser){
            return res.status(400).json({
                status: 'error',
                message: 'User already exists for the given email address.'
            });
        }

        const salt=random();
        const user: any=await createUser({
            email,
            username,
            authentication: {
                salt,
                password: authentication(salt,password),
            },
        });

        return res.status(200).json(user).end();

    }catch(error){
        console.log(error);
        return res.status(400).json({
            status: 'error',
            message: 'Some error from our side. Hang tight we will be fixing it soon.'
        });
    }
}