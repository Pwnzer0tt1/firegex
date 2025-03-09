import { PyFilter, ServerResponse } from "../../js/models"
import { deleteapi, getapi, postapi, putapi } from "../../js/utils"
import { useQuery } from "@tanstack/react-query"

export type Service = {
    service_id:string,
    name:string,
    status:string,
    port:number,
    proto: string,
    ip_int: string,
    n_filters:number,
    edited_packets:number,
    blocked_packets:number,
    fail_open:boolean,
}

export type ServiceAddForm = {
    name:string,
    port:number,
    proto:string,
    ip_int:string,
    fail_open: boolean,
}

export type ServiceSettings = {
    port?:number,
    ip_int?:string,
    fail_open?: boolean,
}

export type ServiceAddResponse = {
    status: string,
    service_id?: string,
}

export const serviceQueryKey = ["nfproxy","services"]

export const nfproxyServiceQuery = () => useQuery({queryKey:serviceQueryKey, queryFn:nfproxy.services})
export const nfproxyServicePyfiltersQuery = (service_id:string) => useQuery({
    queryKey:[...serviceQueryKey,service_id,"pyfilters"],
    queryFn:() => nfproxy.servicepyfilters(service_id)
})

export const nfproxyServiceFilterCodeQuery = (service_id:string) => useQuery({
    queryKey:[...serviceQueryKey,service_id,"pyfilters","code"],
    queryFn:() => nfproxy.getpyfilterscode(service_id)
})

export const nfproxy = {
    services: async () => {
        return await getapi("nfproxy/services") as Service[];
    },
    serviceinfo: async (service_id:string) => {
        return await getapi(`nfproxy/services/${service_id}`) as Service;
    },
    pyfilterenable: async (service_id:string, filter_name:string) => {
        const { status } = await postapi(`nfproxy/services/${service_id}/pyfilters/${filter_name}/enable`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    pyfilterdisable: async (service_id:string, filter_name:string) => {
        const { status } = await postapi(`nfproxy/services/${service_id}/pyfilters/${filter_name}/disable`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestart: async (service_id:string) => {
        const { status } = await postapi(`nfproxy/services/${service_id}/start`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicerename: async (service_id:string, name: string) => {
        const { status } = await putapi(`nfproxy/services/${service_id}/rename`,{ name }) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicestop: async (service_id:string) => {
        const { status } = await postapi(`nfproxy/services/${service_id}/stop`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicesadd: async (data:ServiceAddForm) => {
        return await postapi("nfproxy/services",data) as ServiceAddResponse;
    },
    servicedelete: async (service_id:string) => {
        const { status } = await deleteapi(`nfproxy/services/${service_id}`) as ServerResponse;
        return status === "ok"?undefined:status
    },
    servicepyfilters: async (service_id:string) => {
        return await getapi(`nfproxy/services/${service_id}/pyfilters`) as PyFilter[];
    },
    settings: async (service_id:string, data:ServiceSettings) => {
        const { status } = await putapi(`nfproxy/services/${service_id}/settings`,data) as ServerResponse;
        return status === "ok"?undefined:status
    },
    getpyfilterscode: async (service_id:string) => {
        return await getapi(`nfproxy/services/${service_id}/code`) as string;
    },
    setpyfilterscode: async (service_id:string, code:string) => {
        const { status } = await putapi(`nfproxy/services/${service_id}/code`,{ code }) as ServerResponse;
        return status === "ok"?undefined:status
    }
}


export const EXAMPLE_PYFILTER = `# This in an example of a filter file with http protocol

# From here we can import the DataTypes that we want to use:
# The data type must be specified in the filter functions
# And will also interally be used to decide when call some filters and how aggregate data
from firegex.nfproxy.models import RawPacket

# global context in this execution is dedicated to a single TCP stream
# - This code will be executed once at the TCP stream start
# - The filter will be called for each packet in the stream
# - You can store in global context some data you need, but exceeding with data stored could be dangerous
# - At the end of the stream the global context will be destroyed

from firegex.nfproxy import pyfilter
# pyfilter is a decorator, this will make the function become an effective filter and must have parameters with a specified type

from firegex.nfproxy import REJECT, ACCEPT, UNSTABLE_MANGLE, DROP
# - The filter must return one of the following values:
#   - ACCEPT: The packet will be accepted
#   - REJECT: The packet will be rejected (will be activated a mechanism to send a FIN packet and drop all data in the stream)
#   - UNSTABLE_MANGLE: The packet will be mangled and accepted
#   - DROP: All the packets in this stream will be easly dropped

# If you want, you can use print to debug your filters, but this could slow down the filter

# Filter names must be unique and are specified by the name of the function wrapped by the decorator
@pyfilter
# This function will handle only a RawPacket object, this is the lowest level of the packet abstraction
def strange_filter(packet:RawPacket):
    # Mangling packets can be dangerous, due to instability of the internal TCP state mangling done by the filter below
    # Also is not garanteed that l4_data is the same of the packet data:
    # packet data is the assembled TCP stream, l4_data is the TCP payload of the packet in the nfqueue
    # Unorder packets in TCP are accepted by default, and python is not called in this case
    # For this reason mangling will be only available RawPacket: higher level data abstraction will be read-only
    if b"TEST_MANGLING" in packet.l4_data:
        # It's possible to change teh raw_packet and l4_data values for mangling the packet, data is immutable instead
        packet.l4_data = packet.l4_data.replace(b"TEST", b"UNSTABLE")
        return UNSTABLE_MANGLE
    # Drops the traffic
    if b"BAD DATA 1" in packet.data:
        return DROP
    # Rejects the traffic
    if b"BAD DATA 2" in packet.data:
        return REJECT
    # Accepts the traffic (default if None is returned)
    return ACCEPT

# Example with a higher level of abstraction
@pyfilter
def http_filter(http:HTTPRequest):
    if http.method == "GET" and "test" in http.url:
        return REJECT

# ADVANCED OPTIONS
# You can specify some additional options on the streaming managment
# pyproxy will automatically store all the packets (already ordered by the c++ binary):
#
# If the stream is too big, you can specify what actions to take:
# This can be done defining some variables in the global context
# - FGEX_STREAM_MAX_SIZE: The maximum size of the stream in bytes (default 1MB)
#   NOTE: the stream size is calculated and managed indipendently by the data type handling system
#   Only types required by at least 1 filter will be stored.
# - FGEX_FULL_STREAM_ACTION: The action to do when the stream is full
#   - FullStreamAction.FLUSH: Flush the stream and continue to acquire new packets (default)
#   - FullStreamAction.DROP: Drop the next stream packets - like a DROP action by filter
#   - FullStreamAction.REJECT: Reject the stream and close the connection - like a REJECT action by filter
#   - FullStreamAction.ACCEPT: Stops to call pyfilters and accept the traffic

from firege.nfproxy import FullStreamAction

# Example of a global context
FGEX_STREAM_MAX_SIZE = 4096
FGEX_FULL_STREAM_ACTION = FullStreamAction.REJECT
# This could be an ideal configuration if we expect to normally have streams with a maximum size of 4KB of traffic
`
