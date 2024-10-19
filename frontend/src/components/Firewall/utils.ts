import { useQuery } from "@tanstack/react-query"
import { ServerResponse } from "../../js/models"
import { getapi, postapi } from "../../js/utils"

export enum Protocol {
    TCP = "tcp",
    UDP = "udp",
    BOTH = "both",
    ANY = "any"
}

export enum ActionType {
    ACCEPT = "accept",
    DROP = "drop",
    REJECT = "reject"
}

export enum RuleMode {
    OUT = "out",
    IN = "in",
    FORWARD = "forward"
}

export enum Table {
    MANGLE = "mangle",
    FILTER = "filter",
}

export type Rule = {
    active: boolean
    name:string,
    proto: Protocol,
    src: string,
    dst: string,
    port_src_from: number,
    port_dst_from: number,
    port_src_to: number,
    port_dst_to: number,
    action: ActionType,
    mode: RuleMode,
    table: Table
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

export type FirewallSettings = {
    keep_rules: boolean,
    allow_loopback: boolean,
    allow_established: boolean,
    allow_icmp: boolean,
    multicast_dns: boolean,
    allow_upnp: boolean,
    drop_invalid: boolean,
    allow_dhcp: boolean
}


export type ServerResponseListed = {
    status:(ServerResponse & {rule_id:number})[]|string,
}

export const rulesQueryKey = ["firewall","rules"]
export const firewallRulesQuery = () => useQuery({queryKey:rulesQueryKey, queryFn:firewall.rules, refetchInterval: false})

export const firewall = {
    rules: async() => {
        return await getapi("firewall/rules") as RuleInfo;
    },
    settings: async() => {
        return await getapi("firewall/settings") as FirewallSettings;
    },
    setsettings: async(data:FirewallSettings) => {
        return await postapi("firewall/settings/set", data) as ServerResponse;
    },
    enable: async() => {
        return await getapi("firewall/enable") as ServerResponse;
    },
    disable: async() => {
        return await getapi("firewall/disable") as ServerResponse;
    },
    ruleset: async (data:RuleAddForm) => {
        return await postapi("firewall/rules/set", data) as ServerResponseListed;
    }
}