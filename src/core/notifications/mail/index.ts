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
            .apiConnect(<string>process.env.MAILJET_PUBLIC || "39ba5a8db7daa7adae9e6ff13753bc7f",
                        <string>process.env.MAILJET_PRIVATE || "20eac858fad0be190eee9c430c66e7c3"
            )
            return mailjetConnect.post("send", {version: 'v3.1'}).request({
                Messages: [
                    {
                        From: {
                            Email: <string>process.env.SENDER_EMAIL || 'tchienguenf@gmail.com',
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
                return 5809773 || process.env.LOGIN_TEMPLATE;
            case "forgotpassword":
                return 5809773 || process.env.LOGIN_TEMPLATE;
            case "createuser":
                return 5809783 || process.env.CREATE_ACOUNT_TEMPLATE;
            case "register" :
                return 5809783 || process.env.REGISTER_TEMPLATE;
            case "modifyuser" :
                return 5809781
            case "modifypass" :
                return 5809776
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