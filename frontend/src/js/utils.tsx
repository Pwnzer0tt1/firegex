import { showNotification } from "@mantine/notifications";
import { ImCross } from "react-icons/im";
import { TiTick } from "react-icons/ti"
import { GeneralStats, Service, ServiceAddForm, ServerResponse, RegexFilter, RegexAddForm, ServerStatusResponse, PasswordSend, ChangePassword } from "./models";

var Buffer = require('buffer').Buffer 

export const eventUpdateName = "update-info"

const custom_url = (!process.env.NODE_ENV || process.env.NODE_ENV === 'development')?"http://127.0.0.1:8080":""

export async function getapi(path:string):Promise<any>{
    return await new Promise((resolve, reject) => {
        fetch(`${custom_url}/api/${path}`,{credentials: "same-origin"})
            .then(res => {
                if(res.status === 401) window.location.reload()
                if(!res.ok) reject(res.statusText)
                res.json().then( res => resolve(res) ).catch( err => reject(err))
            })
            .catch(err => {
                reject(err)
            })
    });
}

export async function postapi(path:string,data:any):Promise<any>{
    return await new Promise((resolve, reject) => {
        fetch(`${custom_url}/api/${path}`, {
            method: 'POST',
            credentials: "same-origin",
            cache: 'no-cache',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        }).then(res => {
            if(res.status === 401) window.location.reload()
            if(!res.ok) reject(res.statusText)
            res.json().then( res => resolve(res) ).catch( err => reject(err))
        })
        .catch(err => {
            reject(err)
        })
    });
}

export function fireUpdateRequest(){
    window.dispatchEvent(new Event(eventUpdateName))
}

export async function getstatus(){
    return await getapi(`status`) as ServerStatusResponse;
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

export async function logout(){
    const { status } = await getapi(`logout`) as ServerResponse;
    return status === "ok"?undefined:status 
}

export async function setpassword(data:PasswordSend) {
    const { status } = await postapi("set-password",data) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function changepassword(data:ChangePassword) {
    const { status } = await postapi("change-password",data) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function login(data:PasswordSend) {
    const { status } = await postapi("login",data) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function deleteregex(regex_id:number){
    const { status } = await getapi(`regex/${regex_id}/delete`) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function startservice(service_id:string){
    const { status } = await getapi(`service/${service_id}/start`) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function stopservice(service_id:string){
    const { status } = await getapi(`service/${service_id}/stop`) as ServerResponse;
    return status === "ok"?undefined:status
}
export async function pauseservice(service_id:string){
    const { status } = await getapi(`service/${service_id}/pause`) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function regenport(service_id:string){
    const { status } = await getapi(`service/${service_id}/regen-port`) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function addservice(data:ServiceAddForm) {
    const { status } = await postapi("services/add",data) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function deleteservice(service_id:string) {
    const { status } = await getapi(`service/${service_id}/delete`) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function addregex(data:RegexAddForm) {
    const { status } = await postapi("regexes/add",data) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function serviceregexlist(service_id:string){
    return await getapi(`service/${service_id}/regexes`) as RegexFilter[];
}

const unescapedChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$&'()*+,-./:;<=>?@[\\]^_`{|}~ ";

export function getHumanReadableRegex(regexB64:string){
    const regex = Buffer.from(regexB64, "base64")
    let res = ""
    for (let i=0; i < regex.length; i++){
        const byte = String.fromCharCode(regex[i]);
        if (unescapedChars.includes(byte)){
            res+=byte
        }else{
            let hex_data = regex[i].toString(16)
            if (hex_data.length === 1) hex_data = "0"+hex_data
            res+="%"+hex_data
        }
    }
    return res
}

const hexChars = "0123456789abcdefABCDEF"

export function getBinaryRegex(regexPercentageEncoded:string):number[]{
    const regex = Buffer.from(regexPercentageEncoded)
    let res = []
    for (let i=0; i < regex.length; i++){
        const byte = String.fromCharCode(regex[i]);
        if ("%" === byte){
            if(i+2 < regex.length){
                const byte_1 = String.fromCharCode(regex[i+1]);
                const byte_2 = String.fromCharCode(regex[i+2]);
                if(hexChars.includes(byte_1) && hexChars.includes(byte_2)){
                    res.push(parseInt(byte_1+byte_2,16))
                    i += 2
                }else{
                    res.push(regex[i])
                }
            }else{
                res.push(regex[i])
            }
        }else{
            res.push(regex[i])
        }
    }
    return res
}

export function errorNotify(title:string, description:string ){
    showNotification({
        autoClose: 2000,
        title: title,
        message: description,
        color: 'red',
        icon: <ImCross />,
    });
}

export function okNotify(title:string, description:string ){
    showNotification({
        autoClose: 2000,
        title: title,
        message: description,
        color: 'teal',
        icon: <TiTick />,
    });
}

export function b64encode(data:number[]|string){
    return Buffer.from(data).toString('base64')
}
