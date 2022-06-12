import { GeneralStats, Service, ServiceAddForm, ServerResponse, RegexFilter } from "./models";

export async function getapi(path:string):Promise<any>{
    return await fetch(`/api/${path}`).then( res => res.json() )
}

export async function postapi(path:string,data:any):Promise<any>{
    return await fetch(`/api/${path}`, {
        method: 'POST',
        cache: 'no-cache',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    }).then(res => res.json());
}


export async function generalstats(){
    return await getapi("general-stats") as GeneralStats;
}

export async function servicelist(){
    return await getapi("services") as Service[];
}

export async function serviceinfo(service_id:string){
    return await getapi(`service/${service_id}`) as Service;
}

export async function addservice(data:ServiceAddForm) {
    const { status } = await postapi("services/add",data) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function serviceregexlist(service_id:string){
    return await getapi(`service/${service_id}/regexes`) as RegexFilter[];
}

const unescapedChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$&\'()*+,-./:;<=>?@[\\]^_`{|}~ ";

export function getHumanReadableRegex(regexB64:string){
    var Buffer = require('buffer').Buffer 
    const regex = Buffer.from(regexB64, "base64")
    let res = ""
    for (let i=0; i < regex.length; i++){
        const byte = String.fromCharCode(regex[i]);
        if (unescapedChars.includes(byte)){
            res+=byte
        }else{
            res+="%"+regex[i].toString(16)
        }
    }
    return res
}