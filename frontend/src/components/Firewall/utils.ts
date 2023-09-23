import { RegexAddForm, RegexFilter, ServerResponse } from "../../js/models"
import { getapi, postapi } from "../../js/utils"

export type GeneralStats = {
    rules:number,
}

export enum Protocol {
    TCP = "tcp",
    UDP = "udp",
    ANY = "any"
}

export enum ActionType {
    ACCEPT = "accept",
    DROP = "drop",
    REJECT = "reject"
}

export enum RuleMode {
    OUT = "O",
    IN = "I",
}

export type Rule = {
    active: boolean
    name:string,
    proto: Protocol,
    ip_src: string,
    ip_dst: string,
    port_src_from: number,
    port_dst_from: number,
    port_src_to: number,
    port_dst_to: number,
    action: ActionType,
    mode: RuleMode,
}

export type RuleInfo = {
    rules: Rule[]
    policy: ActionType
}


export type ServerResponseListed = {
    status:(ServerResponse & {rule_id:number})[]|string,
}


export const firewall = {
    stats: async () => {
        return await getapi("firewall/stats") as GeneralStats;
    },
    rules: async() => {
        return await getapi("firewall/rules") as RuleInfo;
    },
    rulenable: async (rule_id:number) => {
        return await getapi(`firewall/rule/${rule_id}/enable`) as ServerResponse;
    },
    ruledisable: async (rule_id:number) => {
        return await getapi(`firewall/rule/${rule_id}/disable`) as ServerResponse;
    },
    rulerename: async (rule_id:number, name: string) => {
        const { status } = await postapi(`firewall/rule/${rule_id}/rename`,{ name }) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicesadd: async (data:RuleInfo) => {
        return await postapi("firewall/rules/set", data) as ServerResponseListed;
    }
}