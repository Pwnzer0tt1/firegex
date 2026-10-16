import { showNotification } from "@mantine/notifications";
import { ImCross } from "react-icons/im";
import { TiTick } from "react-icons/ti"
import { Navigate } from "react-router";
import { ChangePassword, IpInterface, LoginResponse, PasswordSend, ServerResponse, ServerResponseToken, ServerStatusResponse } from "./models";
import { Buffer } from "buffer"
import { QueryClient, useQuery } from "@tanstack/react-query";
import { useMediaQuery } from "@mantine/hooks";
import { io, type Socket } from "socket.io-client";
import { useAuthStore, useSessionStore } from "./store";
import { demoApi, demoSocket } from "./demo";

export const IS_DEV = import.meta.env.DEV
// The public demo build (`bun run build:demo`) answers every request from an in-memory
// backend instead of the network. Vite inlines this as a literal, so a normal build drops
// ./demo and its seed data entirely.
export const IS_DEMO = import.meta.env.VITE_DEMO === "true"

export const regex_ipv6 = "^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$";
export const regex_ipv6_no_cidr = "^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*$";
export const regex_ipv4 = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/(3[0-2]|[1-2][0-9]|[0-9]))?$"
export const regex_ipv4_no_cidr = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
export const regex_port = "^([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?$"
export const regex_range_port = "^(([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])(-([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?)?)?$"
/**
 * What an operator may type where an address is asked for.
 *
 * One rule, read by the pickers, the badges and every form that validates one, because
 * the backend has exactly one too (`utils.is_interface_name` / `parse_ip_or_int`): an
 * interface name is 1-15 characters of `[a-zA-Z0-9_.:-]` that is not already an address.
 * The order matters — `::1` fits the charset as happily as it fits IPv6, and IPv6 is
 * what it means.
 */
export const isIpAddress = (v: string, { cidr = false } = {}) =>
    !!(v.match(cidr ? regex_ipv4 : regex_ipv4_no_cidr) || v.match(cidr ? regex_ipv6 : regex_ipv6_no_cidr))

export const isInterfaceName = (v: string) =>
    !isIpAddress(v, { cidr: true }) && !!v.trim().match(/^[a-zA-Z0-9_.:-]{1,15}$/)

/**
 * Either of them: what a service address accepts, and what the picker offers.
 *
 * A range is an address here too — `10.0.0.0/24:8080` is in the documented set and the
 * backend parses it — except where one address is the whole point, which is the layer
 * that hands traffic to a proxy of the operator's own.
 */
export const isAddressOrInterface = (v: string, { cidr = true } = {}) =>
    isIpAddress(v, { cidr }) || isInterfaceName(v)

/**
 * An address as the operator typed it.
 *
 * The backend parses what it is given and stores it back with a prefix, so `127.0.0.1`
 * comes out of the database as `127.0.0.1/32` — the same address, spelled in a way
 * nobody types and that reads like a range on a row beside real ones. A host-length
 * prefix is dropped for display; a prefix that actually covers more than one address is
 * left exactly as it is, because there it is the whole point.
 */
export const bareAddress = (v: string) => {
    const [addr, prefix] = v.split("/")
    if (prefix === undefined) return v
    return (addr.includes(":") ? prefix === "128" : prefix === "32") ? addr : v
}

// Where `bun run dev` looks for the backend. Overridable because the backend needs
// Linux and NET_ADMIN, so it is often not on the same machine as the dev server.
export const DEV_IP_BACKEND = import.meta.env.VITE_BACKEND ?? "127.0.0.1:4444"

export const WARNING_NFPROXY_TIME_LIMIT = 1000*60*10 // 10 minutes

export type EnumToPrimitiveUnion<T> = `${T & string}` | ParseNumber<`${T & number}`>;
type ParseNumber<T> = T extends `${infer U extends number}` ? U : never;

export function typeCastEnum<E>(value: EnumToPrimitiveUnion<E>): E {
  return value as E;
}

// demoSocket implements the handful of members App.tsx uses; the cast keeps every
// call site typed against the real client.
export const socketio: Socket = IS_DEMO? (demoSocket as unknown as Socket) :
    import.meta.env.DEV?
    io("ws://"+DEV_IP_BACKEND, {
        path:"/sock/socket.io",
        transports: ['websocket'],
        autoConnect: false,
        auth: {
            token: useAuthStore.getState().getAccessToken()
        }
    }):
    io({
        path:"/sock/socket.io",
        transports: ['websocket'],
        autoConnect: false,
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
    if (IS_DEMO) return await demoApi(method, path, data)
    return await new Promise((resolve, reject) => {
        fetch(`${IS_DEV?`http://${DEV_IP_BACKEND}`:""}/api/${path}`, {
            method: method,
            credentials: "same-origin",
            cache: 'no-cache',
            headers: {
              ...(data?{'Content-Type': is_form ? 'application/x-www-form-urlencoded' : 'application/json'}:{}),
              // Omitted rather than sent as the string "null": an unauthenticated app was
              // otherwise offering a credential on every request, which is a 401 the server
              // had to be asked for and the client had to recover from.
              ...(useAuthStore.getState().getAccessToken()
                  ? { "Authorization": "Bearer " + useAuthStore.getState().getAccessToken() }
                  : {})
            },
            body: data? (is_form ? (new URLSearchParams(data)).toString() : JSON.stringify(data)) : undefined
        }).then(res => {
            if(res.status === 401) {
                // Drop the token and let the app re-render from it. Reloading the document
                // here is what made a password screen appear "sometimes on refresh": a token
                // left over from a database that has since been recreated 401s on the first
                // query, the page reloads itself, and what comes back is whatever screen the
                // server's status calls for — "choose a password", if none is set. The app
                // already asks /api/status again when the token changes; that is the same
                // recovery without throwing away the page the operator was looking at.
                useAuthStore.getState().clearAccessToken();
                return reject("Session expired")
            }
            if(res.status === 406) resolve({status:"Wrong Password"})
            if(!res.ok){
                const errorDefault = res.statusText
                return res.json().then( res => reject(getErrorMessageFromServerResponse(res, errorDefault)) ).catch( _err => reject(errorDefault)) 
            }
            // text/plain bodies (a filter's Python source) stay strings: a source file that
            // happens to be valid JSON must not be parsed into a number/array/object
            const isPlainText = (res.headers.get("content-type") ?? "").startsWith("text/plain")
            res.text().then(t => {
                if (isPlainText) return resolve(t)
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

/**
 * The top-level pages that exist. The last one visited is remembered for the tab and sent
 * back to on "/" — so it has to be one of these: a tab open across the upgrade that folded
 * `nfregex`, `nfproxy`, `porthijack` and `tls-decrypt` into `services` remembered one of
 * those, and redirecting to a route that no longer exists landed back here and redirected
 * again, for ever.
 */
export const HOME_SECTIONS = ["services", "firewall"]

export function HomeRedirector(){
    const section = useSessionStore.getState().getHomeSection();
    const path = section && HOME_SECTIONS.includes(section) ? `/${section}` : `/services`
    return <Navigate to={path} replace/>
}

export async function resetfiregex(delete_data:boolean = false){
    const { status } = await postapi("reset",{delete:delete_data}) as ServerResponse;
    return (status === "ok"?undefined:status)
}

export const ipInterfacesQuery = () => useQuery({ queryKey: ["ipinterfaces"], queryFn: getipinterfaces })

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

/** Hand access control to a reverse proxy. Off only — see the backend's `set_auth_mode`. */
export async function setAuthMode(disabled: boolean) {
    const { status } = await postapi("auth-mode", { disabled }) as ServerResponse;
    return status === "ok" ? undefined : status
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