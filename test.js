(async()=>{
    const response = await fetch('http://localhost:3500/oauth/google/login');
    const res = await response.json();
    console.log(res)
})()