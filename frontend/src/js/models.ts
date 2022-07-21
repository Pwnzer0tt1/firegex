export type ServerResponse = {
    status:string
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

export type IpInterface = {
    name:string,
    addr:string
}
