import { useQuery } from "@tanstack/react-query"
import { ServerResponse } from "../../js/models"
import { getapi, postapi } from "../../js/utils"

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
    policy: ActionType,
    enabled: boolean
}

export type RuleAddForm = {
    rules: Rule[]
    policy: ActionType
}


export type ServerResponseListed = {
    status:(ServerResponse & {rule_id:number})[]|string,
}

export const rulesQueryKey = ["firewall","rules"]
export const firewallRulesQuery = () => useQuery({queryKey:rulesQueryKey, queryFn:firewall.rules})

export const firewall = {
    rules: async() => {
        return await getapi("firewall/rules") as RuleInfo;
    },
    enable: async() => {
        return await getapi("firewall/enable") as ServerResponse;
    },
    disable: async() => {
        return await getapi("firewall/disable") as ServerResponse;
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
    servicesadd: async (data:RuleAddForm) => {
        return await postapi("firewall/rules/set", data) as ServerResponseListed;
    }
}