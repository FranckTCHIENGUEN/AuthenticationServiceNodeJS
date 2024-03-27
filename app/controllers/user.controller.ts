import {Body, Get, Put, Route, Security, Tags} from "tsoa";
import {AUTHORIZATION, IResponse, My_Controller} from "./controller";
import {UserModel} from "../models/user";
import {ResponseHandler} from "../../src/config/responseHandler";
import code from "../../src/config/code";
import UserType from "../types/userType";
import {userCreateSchema} from "../validations/user.validation";
// import { PERMISSION } from "../models/permission";
const response = new ResponseHandler()

@Tags("User Controller")
@Route("/user")

export class UserController extends My_Controller {
    @Security(AUTHORIZATION.TOKEN)
    @Get("")
    public async index(
    ): Promise<IResponse> {
        try {
            let findUser = await UserModel.findMany();
            if(!findUser)
                return response.liteResponse(code.FAILD, "Error occurred during Finding ! Try again", null)

            return response.liteResponse(code.SUCCESS, "User found with success !", findUser)
        }catch(e){
            return response.catchHandler(e)
        }
    }

    @Put("edit")
    public async edit(
        @Body() body: UserType.userUpdateFields
    ): Promise<IResponse>{
        try {
            const validate = this.validate(userCreateSchema, body)
            if(validate !== true)
                return response.liteResponse(code.VALIDATION_ERROR, "Validation Error !", validate)

            let userData : any = body

            //found user
            const foundUser = await UserModel.findFirst({where: {email: body.email}})
            if(!foundUser)
                return response.liteResponse(code.NOT_FOUND, 'User not found, Invalid email!')

            const user = await UserModel.update(
                {where:{email: foundUser.id},
                data : {
                    ...userData
                }})
            if (!user)
                return response.liteResponse(code.FAILURE, "An error occurred, on user update. Retry later!", null)


            this.sendMailFromTemplate({
                to : user.email,
                modelName : "modifuser",
                data : {
                    firstName: user.firstName,	},
                subject : "Modify Account"
            })

            console.log("Create user Success")
            return response.liteResponse(code.SUCCESS, "User update with Success !", user)
        }catch (e){
            return response.catchHandler(e)
        }
    }
}