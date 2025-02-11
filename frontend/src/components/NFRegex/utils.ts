import { RegexFilter, ServerResponse } from "../../js/models"
import { deleteapi, getapi, postapi, putapi } from "../../js/utils"
import { RegexAddForm } from "../../js/models"
import { useQuery, useQueryClient } from "@tanstack/react-query"

export type Service = {
    name:string,
    service_id:string,
    status:string,
    port:number,
    proto: string,
    ip_int: string,
    n_packets:number,
    n_regex:number,
}

export type ServiceAddForm = {
    name:string,
    port:number,
    proto:string,
    ip_int:string,
}

export type ServiceAddResponse = {
    status: string,
    service_id?: string,
}

export const serviceQueryKey = ["nfregex","services"]
export const statsQueryKey = ["nfregex","stats"]

export const nfregexServiceQuery = () => useQuery({queryKey:serviceQueryKey, queryFn:nfregex.services})
export const nfregexServiceRegexesQuery = (service_id:string) => useQuery({
    queryKey:[...serviceQueryKey,service_id,"regexes"],
    queryFn:() => nfregex.serviceregexes(service_id)
})

export const nfregex = {
    services: async () => {
        return await getapi("nfregex/services") as Service[];
    },
    serviceinfo: async (service_id:string) => {
        return await getapi(`nfregex/services/${service_id}`) as Service;
    },
    regexdelete: async (regex_id:number) => {
        const { status } = await deleteapi(`nfregex/regexes/${regex_id}`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    regexenable: async (regex_id:number) => {
        const { status } = await postapi(`nfregex/regexes/${regex_id}/enable`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    regexdisable: async (regex_id:number) => {
        const { status } = await postapi(`nfregex/regexes/${regex_id}/disable`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestart: async (service_id:string) => {
        const { status } = await postapi(`nfregex/services/${service_id}/start`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicerename: async (service_id:string, name: string) => {
        const { status } = await putapi(`nfregex/services/${service_id}/rename`,{ name }) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestop: async (service_id:string) => {
        const { status } = await postapi(`nfregex/services/${service_id}/stop`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicesadd: async (data:ServiceAddForm) => {
        return await postapi("nfregex/services",data) as ServiceAddResponse;
    },
    servicedelete: async (service_id:string) => {
        const { status } = await deleteapi(`nfregex/services/${service_id}`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    regexesadd: async (data:RegexAddForm) => {
        const { status } = await postapi("nfregex/regexes",data) as ServerResponse;
        return status === "ok"?undefined:status
    },
    serviceregexes: async (service_id:string) => {
        return await getapi(`nfregex/services/${service_id}/regexes`) as RegexFilter[];
    }
}