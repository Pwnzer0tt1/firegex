

export const update_freq = 2000;
export const notification_time = 1500;

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
    port:number
}

export type ServerResponse = {
    status:string
}

export type ServerStatusResponse = {
    status:string,
    loggined:boolean
}

export type PasswordSend = {
    password:string
}

export type ChangePassword = {
    password:string,
    expire:boolean
}

export type RegexFilter = {
    id:number,
    service_id:string,
    regex:string
    is_blacklist:boolean,
    mode:string //C S B => C->S S->C BOTH
    n_packets:number
}

export type RegexAddForm = {
    service_id:string,
    regex:string,
    is_blacklist:boolean,
    mode:string // C->S S->C BOTH
}