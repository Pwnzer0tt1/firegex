import { GeneralStats, Service } from "./models";

export async function getapi(path:string):Promise<any>{
    return await fetch(`/api/${path}`).then( res => res.json() )
}


export async function generalstats():Promise<GeneralStats>{
    return await getapi("general-stats") as GeneralStats;
}

export async function servicelist():Promise<Service[]>{
    return await getapi("services") as Service[];
}