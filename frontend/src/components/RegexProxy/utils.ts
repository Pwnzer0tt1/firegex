import { RegexAddForm, RegexFilter, ServerResponse } from "../../js/models"
import { getapi, postapi } from "../../js/utils"

export type GeneralStats = {
    services:number,
    closed:number,
    regexes:number
}

export type Service = {
    id:string,
    name:string,
    status:string,
    public_port:number,
    internal_port:number,
    n_packets:number,
    n_regex:number,
}

export type ServiceAddForm = {
    name:string,
    port:number,
    internalPort?:number
}

export type ServerResponseWithID = {
    status:string,
    id:string
}

export type ChangePort = {
    port?: number,
    internalPort?: number
}

export const regexproxy = {
    stats: async () => {
        return await getapi("regexproxy/stats") as GeneralStats;
    },
    services: async() => {
        return await getapi("regexproxy/services") as Service[];
    },
    serviceinfo: async (service_id:string) => {
        return await getapi(`regexproxy/service/${service_id}`) as Service;
    },
    regexdelete: async (regex_id:number) => {
        const { status } = await getapi(`regexproxy/regex/${regex_id}/delete`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    regexenable: async (regex_id:number) => {
        const { status } = await getapi(`regexproxy/regex/${regex_id}/enable`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    regexdisable: async (regex_id:number) => {
        const { status } = await getapi(`regexproxy/regex/${regex_id}/disable`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestart: async (service_id:string) => {
        const { status } = await getapi(`regexproxy/service/${service_id}/start`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestop: async (service_id:string) => {
        const { status } = await getapi(`regexproxy/service/${service_id}/stop`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicepause: async (service_id:string) => {
        const { status } = await getapi(`regexproxy/service/${service_id}/pause`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    serviceregenport: async (service_id:string) => {
        const { status } = await getapi(`regexproxy/service/${service_id}/regen-port`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicechangeport: async (service_id:string, data:ChangePort) => {
        const { status } = await postapi(`regexproxy/service/${service_id}/change-ports`,data) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicesadd: async (data:ServiceAddForm) => {
        return await postapi("regexproxy/services/add",data) as ServerResponseWithID;
    },
    servicerename: async (service_id:string, name: string) => {
        const { status } = await postapi(`regexproxy/service/${service_id}/rename`,{ name }) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicedelete: async (service_id:string) => {
        const { status } = await getapi(`regexproxy/service/${service_id}/delete`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    regexesadd: async (data:RegexAddForm) => {
        const { status } = await postapi("regexproxy/regexes/add",data) as ServerResponse;
        return status === "ok"?undefined:status
    },
    serviceregexes: async (service_id:string) => {
        return await getapi(`regexproxy/service/${service_id}/regexes`) as RegexFilter[];
    }
}