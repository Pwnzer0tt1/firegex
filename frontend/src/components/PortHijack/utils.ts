import { ServerResponse } from "../../js/models"
import { deleteapi, getapi, postapi, putapi } from "../../js/utils"
import { useQuery } from "@tanstack/react-query"

export type GeneralStats = {
    services:number
}

export type Service = {
    name:string,
    service_id:string,
    active:boolean,
    proto: string,
    ip_src: string,
    ip_dst: string,
    proxy_port: number,
    public_port: number,
}

export type ServiceAddForm = {
    name:string,
    public_port:number,
    proxy_port:number,
    proto:string,
    ip_src: string,
    ip_dst: string,
}

export type ServiceAddResponse = ServerResponse & { service_id: string }

export const queryKey = ["porthijack","services"]

export const porthijackServiceQuery = () => useQuery({queryKey, queryFn:porthijack.services})

export const porthijack = {
    services: async () : Promise<Service[]>  => {
        return await getapi("porthijack/services") as Service[];
    },
    serviceinfo: async (service_id:string) => {
        return await getapi(`porthijack/services/${service_id}`) as Service;
    },
    servicestart: async (service_id:string) => {
        const { status } = await postapi(`porthijack/services/${service_id}/start`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicerename: async (service_id:string, name: string) => {
        const { status } = await putapi(`porthijack/services/${service_id}/rename`,{ name }) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestop: async (service_id:string) => {
        const { status } = await postapi(`porthijack/services/${service_id}/stop`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicesadd: async (data:ServiceAddForm) => {
        return await postapi("porthijack/services",data) as ServiceAddResponse;
    },
    servicedelete: async (service_id:string) => {
        const { status } = await deleteapi(`porthijack/services/${service_id}`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    changedestination: async (service_id:string, ip_dst:string, proxy_port:number) => {
        return await putapi(`porthijack/services/${service_id}/change-destination`, {proxy_port, ip_dst}) as ServerResponse;
    }
}