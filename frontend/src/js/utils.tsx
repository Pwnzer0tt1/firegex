import { showNotification } from "@mantine/notifications";
import { ImCross } from "react-icons/im";
import { TiTick } from "react-icons/ti"
import { GeneralStats, Service, ServiceAddForm, ServerResponse, RegexFilter, RegexAddForm, ServerStatusResponse, PasswordSend, ChangePassword, LoginResponse, ServerResponseToken } from "./models";

var Buffer = require('buffer').Buffer 

export const eventUpdateName = "update-info"


export async function getapi(path:string):Promise<any>{

    return await new Promise((resolve, reject) => {
        fetch(`/api/${path}`,{
            credentials: "same-origin",
            headers: { "Authorization" : "Bearer " + window.localStorage.getItem("access_token")}
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

export async function postapi(path:string,data:any,is_form:boolean=false):Promise<any>{
    return await new Promise((resolve, reject) => {
        fetch(`/api/${path}`, {
            method: 'POST',
            credentials: "same-origin",
            cache: 'no-cache',
            headers: {
              'Content-Type': is_form ? 'application/x-www-form-urlencoded' : 'application/json',
              "Authorization" : "Bearer " + window.localStorage.getItem("access_token")
            },
            body: is_form ? data : JSON.stringify(data) 
        }).then(res => {
            if(res.status === 401) window.location.reload() 
            if(res.status === 406) resolve({status:"Wrong Password"})
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

export async function serviceinfo(service_port:number){
    return await getapi(`service/${service_port}`) as Service;
}

export async function logout(){
    window.localStorage.removeItem("access_token")
}

export async function setpassword(data:PasswordSend) {
    const { status, access_token } = await postapi("set-password",data) as ServerResponseToken;
    if (access_token)
        window.localStorage.setItem("access_token", access_token);
    return status === "ok"?undefined:status
}

export async function changepassword(data:ChangePassword) {
    const { status, access_token } = await postapi("change-password",data) as ServerResponseToken;
    console.log(access_token)
    if (access_token)
        window.localStorage.setItem("access_token", access_token);
        return status === "ok"?undefined:status
}

export async function login(data:PasswordSend) {
    const from = "username=login&password=" + encodeURI(data.password);
    const { status, access_token } = await postapi("login",from,true) as LoginResponse;
    window.localStorage.setItem("access_token", access_token);
    return status;
}

export async function deleteregex(regex_id:number){
    const { status } = await getapi(`regex/${regex_id}/delete`) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function activateregex(regex_id:number){
    const { status } = await getapi(`regex/${regex_id}/enable`) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function deactivateregex(regex_id:number){
    const { status } = await getapi(`regex/${regex_id}/disable`) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function startservice(service_port:number){
    const { status } = await getapi(`service/${service_port}/start`) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function renameservice(service_port:number, name: string){
    const { status } = await postapi(`service/${service_port}/rename`,{ name }) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function stopservice(service_port:number){
    const { status } = await getapi(`service/${service_port}/stop`) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function addservice(data:ServiceAddForm) {
    return await postapi("services/add",data) as ServerResponse;
}

export async function deleteservice(service_port:number) {
    const { status } = await getapi(`service/${service_port}/delete`) as ServerResponse;
    return status === "ok"?undefined:status
}


export async function addregex(data:RegexAddForm) {
    const { status } = await postapi("regexes/add",data) as ServerResponse;
    return status === "ok"?undefined:status
}

export async function serviceregexlist(service_port:number){
    return await getapi(`service/${service_port}/regexes`) as RegexFilter[];
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

export function b64decode(regexB64:string){
    return Buffer.from(regexB64, "base64").toString()
}