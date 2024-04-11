import {Body, Get, Post, Request, Route, Security, Tags} from "tsoa";
import {AUTHORIZATION, IResponse, My_Controller} from "./controller";
import UserType from "../types/userType";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import {changePasswordSchema, changForgotePasswordSchema, userCreateSchema} from "../validations/user.validation";
import {SALT_ROUND, UserModel} from "../models/user";
import {ResponseHandler} from "../../src/config/responseHandler";
import code from "../../src/config/code";
import {TokenModel} from "../models/token";
import {otpModel} from "../models/otp";
import {sendSmsData} from "../../src/core/notifications/sms/sendSms";

const response = new ResponseHandler();
const OTP_EXPIRATION_TIME = 300; // 5 minutes in seconds

@Tags("Auth Controller")
@Route("/auth")
export class AuthController extends My_Controller {

    @Post('login')
    public async login(
        @Body() body: UserType.loginFields
    ): Promise<IResponse> {
        try {
            const foundUser = await UserModel.findFirst({ where: { email: body.email } });
            if (!foundUser)
                return response.liteResponse(code.NOT_FOUND, 'Invalid login or password');

            const compare = bcrypt.compareSync(body.password, foundUser.password);
            if (!compare)
                return response.liteResponse(code.FAILURE, "Invalid login or password");

            const otp = this.generateOTP(foundUser.email);

            // send sms
            await this.sendOTP(foundUser, await otp);

            return response.liteResponse(code.SUCCESS, "OTP code was sent to your number");
        } catch (e) {
            console.log(e)
            return response.catchHandler(e);
        }
    }

    @Post('forgot_password')
    public async forgotPassword(
        @Body() body: UserType.forgotPasswordFields
    ): Promise<IResponse> {
        try {
            const foundUser = await UserModel.findFirst({ where: { email: body.email } });
            if (!foundUser)
                return response.liteResponse(code.NOT_FOUND, 'Incorrect email');

            const otp = this.generateOTP(foundUser.email);
            await this.sendOTP(foundUser, await otp);

            return response.liteResponse(code.SUCCESS, "OTP code was sent to your email", { email: foundUser.email });
        } catch (e) {
            return response.catchHandler(e);
        }
    }

    @Post("verify-otp")
    public async verifyOtp(
        @Body() body: UserType.verifyOtp
    ): Promise<IResponse> {
        try {
            const foundUser = await UserModel.findFirst({ where: { email: body.email } });
            if (!foundUser)
                return response.liteResponse(code.NOT_FOUND, 'User not found, Invalid email !');

            const foundOTP = await otpModel.findFirst({ where: { otp: body.otp, userEmail: body.email } });
            if (!foundOTP)
                return response.liteResponse(code.NOT_FOUND, "Incorrect OTP, try again !");

            if (foundOTP.expiredIn < Math.round(new Date().getTime() / 1000))
                return response.liteResponse(code.FAILURE, "This OTP has expired. Resend OTP !");

            const user={
                email:foundUser.email,
               lastName:foundUser.lastName!,
               firstName:foundUser.firstName
            }

            const jwtToken = await this.generateToken(foundUser.id, foundUser.email);
            return response.liteResponse(code.SUCCESS, "Success request login", { user: user, token: jwtToken });
        } catch (e) {
            return response.catchHandler(e);
        }
    }

    @Post('resend-otp')
    public async resendotp(
        @Body() body: UserType.resendOtp
    ): Promise<IResponse> {
        try {
            const foundUser = await UserModel.findFirst({ where: { email: body.email } });
            if (!foundUser)
                return response.liteResponse(code.NOT_FOUND, 'User not found, Invalid email');

            await otpModel.deleteMany({
                where: {
                    userEmail: body.email,
                    expiredIn: { gt: Math.round(new Date().getTime() / 1000)}
                }
            });

            const otp = this.generateOTP(foundUser.email);
            await this.sendOTP(foundUser, await otp);

            return response.liteResponse(code.SUCCESS, "OTP code is resent", { otp });
        } catch (e) {
            return response.catchHandler(e);
        }
    }

    @Post('change_password')
    @Security(AUTHORIZATION.TOKEN)
    public async changePassword(
        @Body() body: UserType.changePasswordFields
    ): Promise<IResponse> {
        try {

            let validate = this.validate(changePasswordSchema, body);

            if (body.oldPassword == null){
                 validate = this.validate(changForgotePasswordSchema, body);
            }
            if (validate !== true)
                return response.liteResponse(code.VALIDATION_ERROR, "Validation Error !", validate);

            const foundUser = await UserModel.findFirst({ where: { email: body.email } });
            if (!foundUser)
                return response.liteResponse(code.NOT_FOUND, 'User not found, Invalid email!');

            if (body.oldPassword != null){
                if (!bcrypt.compareSync(body.oldPassword, foundUser.password))
                    return response.liteResponse(code.FAILURE, 'Invalid password!');
            }

            const updatedUser = await UserModel.update({
                data: { password: bcrypt.hashSync(body.newPassword, SALT_ROUND) },
                where: { id: foundUser.id }
            });

            if (!updatedUser)
                return response.liteResponse(code.FAILURE, 'Something went wrong, try Again !', null);

            return response.liteResponse(code.SUCCESS, "Your password is updated", null);
        } catch (e) {
            return response.catchHandler(e);
        }
    }

    @Post("register")
    public async register(
        @Body() body: UserType.userCreateFields
    ): Promise<IResponse> {
        try {
            const validate = this.validate(userCreateSchema, body);
            if (validate !== true)
                return response.liteResponse(code.VALIDATION_ERROR, "Validation Error !", validate);

            const existingUser = await UserModel.findFirst({ where: { email: body.email } });
            if (existingUser)
                return response.liteResponse(code.FAILURE, "Email already exists, try with another email");

            const hashedPassword = await bcrypt.hash(body.password, SALT_ROUND);
            const newUser = await UserModel.create({ data: { ...body, password: hashedPassword } });

            if (!newUser)
                return response.liteResponse(code.FAILURE, "An error occurred while creating the user. Retry later!", null);

            return response.liteResponse(code.SUCCESS, "User registered successfully !", newUser);
        } catch (e) {
            return response.catchHandler(e);
        }
    }

    @Get('logout')
    @Security(AUTHORIZATION.TOKEN)
    public async logout(
        @Request() req: any
    ): Promise<IResponse> {
        try {
            const authorization = req.headers['authorization'] as string;
            const token = await TokenModel.findFirst({ where: { jwt: authorization.split(' ').pop() } });
            if (!token)
                return response.liteResponse(code.FAILURE, "Token not found", null);

            const expiry = Math.round(new Date().getTime() / 1000) / 2;
            await TokenModel.update({ where: { id: token.id }, data: { expireIn: expiry } });

            return response.liteResponse(code.SUCCESS, "Logout successful !", null);
        } catch (e) {
            return response.catchHandler(e);
        }
    }

    public async generateToken(user_id: string, email: string): Promise<string> {
        const payload: any = { userId: user_id, email: email };
        const token = jwt.sign(payload, process.env.SECRET_TOKEN!, { expiresIn: '1d' });
        const decoded: any = jwt.decode(token);

        await TokenModel.create({
            data: { userId: user_id, jwt: token, expireIn: decoded.exp },
            select: { jwt: true }
        });

        return token;
    }

    private async generateOTP(mail: string): Promise<number> {
        // Implement OTP generation logic here
        const otp = this.generate_otp()// Example OTP generation (6 digits)
        const savedOtp = await otpModel.create({
            data: {
                otp: otp,
                expiredIn: (Math.round(new Date().getTime() / 1000)) + OTP_EXPIRATION_TIME,
                userEmail: mail
            }
        })

        if (!savedOtp)
            return response.liteResponse(code.FAILURE, 'Something went wrong, try Again !', null);

        return otp;
    }

    private async sendOTP(user: any, otp: number): Promise<void> {

        const config:sendSmsData={
            to:user.region+user.phoneNumber,
            from:'Digisoft',
            text:`your otp code is : ${otp}`
        }
        // await this.sendSms(config);
        console.log(`OTP sent to ${user.region}${user.phoneNumber}: ${otp}`);

    }
}
