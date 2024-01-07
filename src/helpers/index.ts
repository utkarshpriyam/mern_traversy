/**
 * Authentication helpers to either encrypt a password or to create a random token
 */

import crypto from 'crypto';

export const random = ()=>crypto.randomBytes(128).toString('base64');
export const authentication = (salt: string, password: string)=>{
    return crypto.createHmac('sha256', [salt,password].join('/')).update(process.env.AUTHENTICATION_SECRET).digest('hex');
};