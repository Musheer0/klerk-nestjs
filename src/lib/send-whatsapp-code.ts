
export const sendWhatsAppCode  =async(code:string, reciver:string)=>{
   fetch(`https://graph.facebook.com/v22.0/${process.env.PHONE_NUMBER_ID}/messages`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${process.env.WHATSAPP_ACCESS_TOKEN}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    messaging_product: 'whatsapp',
    to: reciver.split('+')[1],
        "recipient_type": "individual",
   "type": "text",
    "text": {
        "body": `${code} is your otp to verify your phone number`,
        
    }
  })
})
.then(res => res.json())
.then(data => console.log(data))
.catch(err => console.error('Fetch error:', err));

}