import { showNotification } from "@mantine/notifications";
import { ImCross } from "react-icons/im";
import { TiTick } from "react-icons/ti"
import { Navigate } from "react-router-dom";
import { nfregex } from "../components/NFRegex/utils";
import { regexproxy } from "../components/RegexProxy/utils";
import { ChangePassword, IpInterface, LoginResponse, PasswordSend, ServerResponse, ServerResponseToken, ServerStatusResponse } from "./models";
import { Buffer } from "buffer"


export const eventUpdateName = "update-info"

export const regex_ipv6 = "^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$";
export const regex_ipv6_no_cidr = "^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*$";
export const regex_ipv4 = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/(3[0-2]|[1-2][0-9]|[0-9]))?$"
export const regex_ipv4_no_cidr = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

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

export function getmainpath(){
    const paths = window.location.pathname.split("/")
    if (paths.length > 1) return paths[1]
    return ""
}

export function getapiobject(){
    switch(getmainpath()){
        case "nfregex":
            return nfregex
        case "regexproxy":
            return regexproxy
      }
      throw new Error('No api for this tool!');
}

export function HomeRedirector(){
    const section = sessionStorage.getItem("home_section")
    const path = section?`/${section}`:`/nfregex`
    return <Navigate to={path} />
}

export function fireUpdateRequest(){
    window.dispatchEvent(new Event(eventUpdateName))
}


export async function resetfiregex(delete_data:boolean = false){
    const { status } = await postapi("reset",{delete:delete_data}) as ServerResponse;
    return (status === "ok"?undefined:status)
}

export async function getipinterfaces(){
    return await getapi("interfaces") as IpInterface[];
}

export async function getstatus(){
    return await getapi(`status`) as ServerStatusResponse;
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
