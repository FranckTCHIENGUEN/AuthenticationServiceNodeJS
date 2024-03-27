import dotenv from "dotenv";
import {Controller} from "tsoa";
// import cloudinary from "cloudinary";
import Mailer from "../../src/core/notifications/mail";
// import {USER_ROLE} from "../models/role";
import {TokenModel} from "../models/token";
import * as stream from "stream";



export enum AUTHORIZATION  {
    TOKEN = "Jwt"   
};

dotenv.config();


export interface IResponse {
    code : number,

    message ?: string,

    data?: any
}

export class My_Controller extends Controller {


    public validate (schema: any, fields:any) : boolean | object {
        
        const validation  = schema.validate(fields,  { abortEarly: false });
        let errors : any = {};
        if (validation.error){
            for (const field of validation.error.details){
                errors[field.context.key] = field.message
            }
            return errors;
        }else {
            return true
        }
        
    }

    public generatePassword = (): string => {
        let result = '';
        let characters = <string>process.env.RANDOM_PASSWORD || "1234567890qwertyuyiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
        let slugLength = characters.length
        for ( let i = 0; i < 15; i++ ) {
            result += characters.charAt(Math.floor(Math.random() *
                slugLength));
        }
        return result;
    }


    public generate_otp() : number{
        const otpTable = ['0','1','2','3','4','5','6','7','8','9']
        const random = [];
        for(let i = 0; i<4; i++){
         random.push(Math.floor(Math.random() * otpTable.length))
        }
        const otp = random.join('').substring(0, 4)
        return parseInt(otp)
    }

    public async sendMail (config : {
        to : string | string[],
        subject : string,
        modelName : string,
        data ?: object
    }) : Promise<void> {
        return await Mailer.sendFromTemplate(config.to, config.subject, "", config.modelName, config.data);
    }

    public async sendMailFromTemplate (config : {
        to : string | string[],
        subject : string,
        modelName : string,
        data ?: object
    }) : Promise<any> {
        return await Mailer.sendFromTemplate(config.to, config.subject, "", config.modelName, config.data);
    }

    public async getUserId(token: string | undefined): Promise<any> {
        return TokenModel.findFirst({
            where: {
                jwt: token
            },
            select: {
                userId: true
            }
        });
    }

}

