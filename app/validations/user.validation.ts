import Joi from "joi";
import  {schema}  from "../utils/schema";

export const userCreateSchema = Joi.object({
    firstName : schema.firstName,
    lastName : schema.lastName,
    email : schema.email,
    phoneNumber : schema.phoneNumber,
    region : schema.region,
    password : schema.password,
})
export const userUpdateSchema = Joi.object({
    firstName : schema.firstName,
    lastName : schema.lastName,
    email : schema.email,
})

export const loginSchema = Joi.object({
    email : schema.email,
    password : schema.password
})


export const forgotSchema = Joi.object({
    password : schema.password
})

export const changePasswordSchema = Joi.object({
    email : schema.email,
    oldPassword : schema.password,
    newPassword : schema.password
})
export const changForgotePasswordSchema = Joi.object({
    email : schema.email,
    newPassword : schema.password
})