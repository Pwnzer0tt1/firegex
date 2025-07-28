import { showNotification } from "@mantine/notifications";
import { ImCross } from "react-icons/im";
import { TiTick } from "react-icons/ti"
import { Navigate } from "react-router-dom";
import { ChangePassword, IpInterface, LoginResponse, PasswordSend, ServerResponse, ServerResponseToken, ServerStatusResponse } from "./models";
import { Buffer } from "buffer"
import { QueryClient, useQuery } from "@tanstack/react-query";
import { useMediaQuery } from "@mantine/hooks";
import { io } from "socket.io-client";
import { useAuthStore, useSessionStore } from "./store";

export const IS_DEV = import.meta.env.DEV

export const regex_ipv6 = "^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$";
export const regex_ipv6_no_cidr = "^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*$";
export const regex_ipv4 = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/(3[0-2]|[1-2][0-9]|[0-9]))?$"
export const regex_ipv4_no_cidr = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
export const regex_port = "^([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?$"
export const regex_range_port = "^(([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])(-([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?)?)?$"
export const DEV_IP_BACKEND = "127.0.0.1:4444"

export const WARNING_NFPROXY_TIME_LIMIT = 1000*60*10 // 10 minutes

export type EnumToPrimitiveUnion<T> = `${T & string}` | ParseNumber<`${T & number}`>;
type ParseNumber<T> = T extends `${infer U extends number}` ? U : never;

export function typeCastEnum<E>(value: EnumToPrimitiveUnion<E>): E {
  return value as E;
}

export const socketio = import.meta.env.DEV?
    io("ws://"+DEV_IP_BACKEND, {
        path:"/sock/socket.io",
        transports: ['websocket'],
        auth: {
            token: useAuthStore.getState().getAccessToken()
        }
    }):
    io({
        path:"/sock/socket.io",
        transports: ['websocket'],
        auth: {
            token: useAuthStore.getState().getAccessToken()
        }
    })

export const queryClient = new QueryClient({ defaultOptions: { queries: {
    staleTime: Infinity
} }})

export function getErrorMessage(e: any) {
	let error = "Unknown error";
    if(typeof e == "string") return e
	if (e.response) {
		// The request was made and the server responded with a status code
		// that falls out of the range of 2xx
		error = e.response.data.error;
	} else {
		// Something happened in setting up the request that triggered an Error
		error = e.message || e.error;
	}
	return error;
}

export function getErrorMessageFromServerResponse(e: any, def:string = "Unknown error") {
    if (e.status){
        return e.status
    }
    if (e.detail){
        if (typeof e.detail == "string")
            return e.detail
        if (e.detail[0] && e.detail[0].msg)
            return e.detail[0].msg
    }
    if (e.error){
        return e.error
    }
    return def
}


export async function genericapi(method:string,path:string,data:any = undefined, is_form:boolean=false):Promise<any>{
    return await new Promise((resolve, reject) => {
        fetch(`${IS_DEV?`http://${DEV_IP_BACKEND}`:""}/api/${path}`, {
            method: method,
            credentials: "same-origin",
            cache: 'no-cache',
            headers: {
              ...(data?{'Content-Type': is_form ? 'application/x-www-form-urlencoded' : 'application/json'}:{}),
              "Authorization" : "Bearer " + useAuthStore.getState().getAccessToken()
            },
            body: data? (is_form ? (new URLSearchParams(data)).toString() : JSON.stringify(data)) : undefined
        }).then(res => {
            if(res.status === 401) window.location.reload() 
            if(res.status === 406) resolve({status:"Wrong Password"})
            if(!res.ok){
                const errorDefault = res.statusText
                return res.json().then( res => reject(getErrorMessageFromServerResponse(res, errorDefault)) ).catch( _err => reject(errorDefault)) 
            }
            res.text().then(t => {
                try{
                    resolve(JSON.parse(t))
                }catch(e){
                    resolve(t)
                }
            }).catch( err => reject(err))
        }).catch(err => {
            reject(err)
        })
    });
}

export async function getapi(path:string):Promise<any>{
    return await genericapi("GET",path)
}

export async function postapi(path:string,data:any=undefined,is_form:boolean=false):Promise<any>{
    return await genericapi("POST",path,data,is_form)
}

export async function deleteapi(path:string):Promise<any>{
    return await genericapi("DELETE",path)
}

export async function putapi(path:string,data:any):Promise<any>{
    return await genericapi("PUT",path,data)
}

export function getMainPath(){
    const paths = window.location.pathname.split("/")
    if (paths.length > 1) return paths[1]
    return ""
}

export function HomeRedirector(){
    const section = useSessionStore.getState().getHomeSection();
    const path = section?`/${section}`:`/nfregex`
    return <Navigate to={path} replace/>
}

export async function resetfiregex(delete_data:boolean = false){
    const { status } = await postapi("reset",{delete:delete_data}) as ServerResponse;
    return (status === "ok"?undefined:status)
}

export const ipInterfacesQuery = () => useQuery(["ipinterfaces"], getipinterfaces)

export async function getipinterfaces(){
    return await getapi("interfaces") as IpInterface[];
}

export async function getstatus(){
    return await getapi(`status`) as ServerStatusResponse;
}

export async function logout(){
    useAuthStore.getState().clearAccessToken();
}

export async function setpassword(data:PasswordSend) {
    const { status, access_token } = await postapi("set-password",data) as ServerResponseToken;
    if (access_token)
        useAuthStore.getState().setAccessToken(access_token);
    return status === "ok"?undefined:status
}

export async function changepassword(data:ChangePassword) {
    const { status, access_token } = await postapi("change-password",data) as ServerResponseToken;
    if (access_token)
        useAuthStore.getState().setAccessToken(access_token);
        return status === "ok"?undefined:status
}

export async function login(data:PasswordSend) {
    const from = {username: "login", password: data.password};
    const { status, access_token } = await postapi("login",from,true) as LoginResponse;
    useAuthStore.getState().setAccessToken(access_token);
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

export const makeid = (length:number) => {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    let counter = 0;
    while (counter < length) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
      counter += 1;
    }
    return result;
}

export function b64encode(data:number[]|string){
    return Buffer.from(data).toString('base64')
}

export function b64decode(regexB64:string){
    return Buffer.from(regexB64, "base64").toString()
}

export function isMediumScreen(){
    return useMediaQuery('(min-width: 600px)');
}

export function isLargeScreen(){
    return useMediaQuery('(min-width: 992px)');
}