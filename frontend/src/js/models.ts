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
export type ServerResponseWithID = {
    status:string,
    id:string
}

export type ServerResponseToken = {
    status:string,
    access_token?:string
}

export type LoginResponse = {
    status?:string,
    access_token:string,
    token_type:string
}

export type ServerStatusResponse = {
    status:string,
    loggined:boolean
}

export type PasswordSend = {
    password:string,
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
    is_case_sensitive:boolean,
    mode:string //C S B => C->S S->C BOTH
    n_packets:number,
    active:boolean
}

export type RegexAddForm = {
    service_id:string,
    regex:string,
    is_case_sensitive:boolean,
    is_blacklist:boolean,
    mode:string // C->S S->C BOTH
}