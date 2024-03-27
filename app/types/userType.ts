
import { defaultEmail } from "./defaults/email.types"
import { defaultFisrtName } from "./defaults/firstName.type"
import { defaultLastName } from "./defaults/lastName.type"
import { defaultOtp } from "./defaults/otp.type"
import {VERIF_TYPE} from "./defaults/verificationTpe";

declare namespace UserType {
    export interface userCreateFields {
        firstName : defaultFisrtName,
        lastName ?: defaultLastName,
        email : defaultEmail,
        password: string,
    }
    export interface userUpdateFields {
        firstName : defaultFisrtName,
        lastName ?: defaultLastName,
        email : defaultEmail,
    }

    export interface verifiedFields {
        new_password: string,
        email: defaultEmail,
        token: string
    }

    export interface loginFields {
        email: defaultEmail,
        password : string
    }

    export interface forgotPasswordFields {
        email: defaultEmail,
    }

    export interface changePasswordFields {
        email: defaultEmail,
        oldPassword: string
        newPassword: string
    }

    export interface verifyOtp {
        email: defaultEmail,
        otp: defaultOtp;
        verificationType:VERIF_TYPE
    }

    export interface resendOtp {
        email: defaultEmail,
    }
}
export default UserType

