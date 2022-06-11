

export const update_freq = 3000;

export type GeneralStats = {
    services:number,
    closed:number,
    regex:number
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
