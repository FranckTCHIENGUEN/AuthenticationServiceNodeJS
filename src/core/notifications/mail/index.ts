import Mailjet from "node-mailjet"


export interface MailFormat{
    from: string;
    to: string;
    subject: string;
    message?: string;
    html?: string;
    text?: string;
}

class Mailer {

        /**
     * @params to String sender address
     * @params subject String email subject
     * @params modelMane String the reference model name for the mail
     * @params data Object the mapping data between model and real data
     * @params path String the modele file path (disturbing because if fs )
     */

    async sendFromTemplate(to: string | string[], subject: string, language: string, modelName: string, data?: object): Promise<any> {
        try{
            // let message = await this.normalizeModel(modelName, language, data);
            // return await this.send(to, subject, message, language);
            const mailjetConnect = Mailjet
            .apiConnect(<string>process.env.MAILJET_PUBLIC || "a47c3858e13be8df5f3bfeef7b8103f0",
                        <string>process.env.MAILJET_PRIVATE || "900cf41666567419b69c202b5b3b31fa"
            )
            console.log(to)
            return mailjetConnect.post("send", {version: 'v3.1'}).request({
                Messages: [
                    {
                        From: {
                            Email: <string>process.env.SENDER_EMAIL || 'k.becker@psatechnologie.com',
                            Name: <string>process.env.SENDER_NAME || 'DIGISOFT',
                        },
                        To: this.receiver(to),
                        TemplateID: this.selectTemplateModel(modelName),
                        TemplateLanguage: true,
                        Subject: subject,
                        Variables: this.organizeData(data)
                    }
                ]
            })

        } catch(error){
            console.log(error);
        }
    }

    selectTemplateModel (modelName: string): number{

        switch( modelName ){
            case "login":
                return 5831431 || process.env.LOGIN_TEMPLATE;
            case "verification":
                return 5833445 || process.env.LOGIN_TEMPLATE;
            case "5831435":
                return 5809783 || process.env.CREATE_ACOUNT_TEMPLATE;
            case "forgotpassword":
                return 5831440 || process.env.CREATE_ACOUNT_TEMPLATE;
            case "register" :
                return 5809783 || process.env.REGISTER_TEMPLATE;
            case "modifyuser" :
                return 5831433
            case "modifypass" :
                return 5831431
            default :
                throw new Error("Unknown modelName")
        }
    
    }
    receiver (to: string | string[]) : any {
        const response = []
        if(typeof(to) == "string"){
            let sender = {
                Email: to,
                Name: to
            }
            response.push(sender)
            return response
        } else {
            for(let item of to){
                let sender = {
                    Email : item,
                    Name : item
                }
                response.push(sender)
            }
            return response
        } 
    }

    organizeData (data : any) : any {
        const result: any = {}
        let keys = Object.keys(data)
        let values = Object.values(data)
        keys.forEach((element, index) => {
                result[element] = values[index]
        })
        return result
        }

}

export default (new Mailer())