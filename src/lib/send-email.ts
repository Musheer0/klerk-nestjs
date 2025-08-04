import { Resend } from 'resend';
const resend = new Resend(process.env.RESEND);
export const sendEmail = async(email:string,template:string,title:string)=>{
     const { data, error } = await resend.emails.send({
    from: 'Klerk <onboarding@resend.dev>',
    to: process.env.NODE_ENV==='production'? email: process.env.TEST_EMAIL!,
    subject: title,
    html: template,
  });

  if (error) {
    return console.error({ error });
  }

  console.log({ data });
}
