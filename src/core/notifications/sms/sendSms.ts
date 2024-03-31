const { Vonage } = require('@vonage/server-sdk')

const vonage = new Vonage({
    apiKey: "7b4e8f0c",
    apiSecret: "testAuthApi1"
})

export interface sendSmsData{
    to:string,
    from:string,
    text:string
}

class Sms{


   private  async  sendSMS(to:string, from:string, text:string) {

       await vonage.sms.send({to, from, text})
            .then((resp: any) => { console.log('Message sent successfully'); console.log(resp); })
            .catch((err: any) => { console.log('There was an error sending the messages.'); console.error(err); });
    }

    async sendSms(smsData:sendSmsData){
        await this.sendSMS(smsData.to, smsData.from, smsData.text);
    }

}



export default (new Sms())