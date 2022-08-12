import { ServerResponse } from "../../js/models"
import { getapi, postapi } from "../../js/utils"

export type GeneralStats = {
    services:number
}

export type Service = {
    name:string,
    service_id:string,
    active:boolean,
    port:number,
    proto: string,
    ip_int: string,
    proxy_port: number,
    public_port: number,
}

export type ServiceAddForm = {
    name:string,
    public_port:number,
    proxy_port:number,
    proto:string,
    ip_int:string,
}

export type ServiceAddResponse = {
    status: string,
    service_id?: string,
}

export const porthijack = {
    stats: async () => {
        return await getapi("porthijack/stats") as GeneralStats;
    },
    services: async () => {
        return await getapi("porthijack/services") as Service[];
    },
    serviceinfo: async (service_id:string) => {
        return await getapi(`porthijack/service/${service_id}`) as Service;
    },
    servicestart: async (service_id:string) => {
        const { status } = await getapi(`porthijack/service/${service_id}/start`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicerename: async (service_id:string, name: string) => {
        const { status } = await postapi(`porthijack/service/${service_id}/rename`,{ name }) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestop: async (service_id:string) => {
        const { status } = await getapi(`porthijack/service/${service_id}/stop`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicesadd: async (data:ServiceAddForm) => {
        return await postapi("porthijack/services/add",data) as ServiceAddResponse;
    },
    servicedelete: async (service_id:string) => {
        const { status } = await getapi(`porthijack/service/${service_id}/delete`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    changeport: async (service_id:string, proxy_port:number) => {
        return await postapi(`porthijack/service/${service_id}/changeport`, {proxy_port}) as ServerResponse;
    }
}