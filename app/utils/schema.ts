import BaseJoi from "joi";
import JoiDate from '@joi/date';
const Joi = BaseJoi.extend(JoiDate)

export const schema = {
    email : Joi.string().email().required(),
    password : Joi.string()
        .required()
        .min(8)
        .pattern(new RegExp(/^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})/))
        .message('Entez un mot de passe contenant des chiffre et lettre'),
    firstName : Joi.string().min(1).required(),
    phoneNumber : Joi.string().min(1).required(),
    region : Joi.string().min(1).required(),
    lastName : Joi.string().min(1).optional(),
    id : Joi.number().required(),
    stringText: Joi.string().required(),

}
    
