import { RegexFilter, ServerResponse } from "../../js/models"
import { getapi, postapi } from "../../js/utils"
import { RegexAddForm } from "../../js/models"

export type GeneralStats = {
    services:number,
    closed:number,
    regexes:number
}

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