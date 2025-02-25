import { PyFilter, ServerResponse } from "../../js/models"
import { deleteapi, getapi, postapi, putapi } from "../../js/utils"
import { useQuery } from "@tanstack/react-query"

export type Service = {
    service_id:string,
    name:string,
    status:string,
    port:number,
    proto: string,
    ip_int: string,
    n_filters:number,
    edited_packets:number,
    blocked_packets:number,
    fail_open:boolean,
}

export type ServiceAddForm = {
    name:string,
    port:number,
    proto:string,
    ip_int:string,
    fail_open: boolean,
}

export type ServiceSettings = {
    port?:number,
    ip_int?:string,
    fail_open?: boolean,
}

export type ServiceAddResponse = {
    status: string,
    service_id?: string,
}

export const serviceQueryKey = ["nfproxy","services"]

export const nfproxyServiceQuery = () => useQuery({queryKey:serviceQueryKey, queryFn:nfproxy.services})
export const nfproxyServicePyfiltersQuery = (service_id:string) => useQuery({
    queryKey:[...serviceQueryKey,service_id,"pyfilters"],
    queryFn:() => nfproxy.servicepyfilters(service_id)
})

export const nfproxyServiceFilterCodeQuery = (service_id:string) => useQuery({
    queryKey:[...serviceQueryKey,service_id,"pyfilters","code"],
    queryFn:() => nfproxy.getpyfilterscode(service_id)
})

export const nfproxy = {
    services: async () => {
        return await getapi("nfproxy/services") as Service[];
    },
    serviceinfo: async (service_id:string) => {
        return await getapi(`nfproxy/services/${service_id}`) as Service;
    },
    pyfilterenable: async (filter_name:string) => {
        const { status } = await postapi(`nfproxy/pyfilters/${filter_name}/enable`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    pyfilterdisable: async (filter_name:string) => {
        const { status } = await postapi(`nfproxy/pyfilters/${filter_name}/disable`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestart: async (service_id:string) => {
        const { status } = await postapi(`nfproxy/services/${service_id}/start`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicerename: async (service_id:string, name: string) => {
        const { status } = await putapi(`nfproxy/services/${service_id}/rename`,{ name }) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestop: async (service_id:string) => {
        const { status } = await postapi(`nfproxy/services/${service_id}/stop`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicesadd: async (data:ServiceAddForm) => {
        return await postapi("nfproxy/services",data) as ServiceAddResponse;
    },
    servicedelete: async (service_id:string) => {
        const { status } = await deleteapi(`nfproxy/services/${service_id}`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicepyfilters: async (service_id:string) => {
        return await getapi(`nfproxy/services/${service_id}/pyfilters`) as PyFilter[];
    },
    settings: async (service_id:string, data:ServiceSettings) => {
        const { status } = await putapi(`nfproxy/services/${service_id}/settings`,data) as ServerResponse;
        return status === "ok"?undefined:status
    },
    getpyfilterscode: async (service_id:string) => {
        return await getapi(`nfproxy/services/${service_id}/pyfilters/code`) as string;
    },
    setpyfilterscode: async (service_id:string, code:string) => {
        const { status } = await putapi(`nfproxy/services/${service_id}/pyfilters/code`,{ code }) as ServerResponse;
        return status === "ok"?undefined:status
    }
}
