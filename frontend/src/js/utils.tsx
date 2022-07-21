import { showNotification } from "@mantine/notifications";
import { ImCross } from "react-icons/im";
import { TiTick } from "react-icons/ti"
import { GeneralStats, Service, ServiceAddForm, ServerResponse, RegexFilter, RegexAddForm, ServerStatusResponse, PasswordSend, ChangePassword, LoginResponse, ServerResponseToken, ServiceAddResponse, IpInterface } from "./models";

var Buffer = require('buffer').Buffer 

export const eventUpdateName = "update-info"

export const regex_ipv6 = "^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$";
export const regex_ipv4 = "^([0-9]{1,3}\\.){3}[0-9]{1,3}(\\/([0-9]|[1-2][0-9]|3[0-2]))?$"

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

export const nfregex = {
    stats: async () => {
        return await getapi("nfregex/stats") as GeneralStats;
    },
    services: async () => {
        return await getapi("nfregex/services") as Service[];
    },
    serviceinfo: async (service_id:string) => {
        return await getapi(`nfregex/service/${service_id}`) as Service;
    },
    regexdelete: async (regex_id:number) => {
        const { status } = await getapi(`nfregex/regex/${regex_id}/delete`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    regexenable: async (regex_id:number) => {
        const { status } = await getapi(`nfregex/regex/${regex_id}/enable`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    regexdisable: async (regex_id:number) => {
        const { status } = await getapi(`nfregex/regex/${regex_id}/disable`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestart: async (service_id:string) => {
        const { status } = await getapi(`nfregex/service/${service_id}/start`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicerename: async (service_id:string, name: string) => {
        const { status } = await postapi(`nfregex/service/${service_id}/rename`,{ name }) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestop: async (service_id:string) => {
        const { status } = await getapi(`nfregex/service/${service_id}/stop`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicesadd: async (data:ServiceAddForm) => {
        return await postapi("nfregex/services/add",data) as ServiceAddResponse;
    },
    servicedelete: async (service_id:string) => {
        const { status } = await getapi(`nfregex/service/${service_id}/delete`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    regexesadd: async (data:RegexAddForm) => {
        const { status } = await postapi("nfregex/regexes/add",data) as ServerResponse;
        return status === "ok"?undefined:status
    },
    serviceregexes: async (service_id:string) => {
        return await getapi(`nfregex/service/${service_id}/regexes`) as RegexFilter[];
    }
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