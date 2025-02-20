from inspect import signature
from firegex.nfproxy.params import RawPacket, NotReadyToRun
from firegex.nfproxy import ACCEPT, DROP, REJECT, MANGLE, EXCEPTION, INVALID

RESULTS = [
    ACCEPT,
    DROP,
    REJECT,
    MANGLE,
    EXCEPTION,
    INVALID
]
FULL_STREAM_ACTIONS = [
    "flush"
    "accept",
    "reject",
    "drop"
]

type_annotations_associations = {
    "tcp": {
        RawPacket: RawPacket.fetch_from_global
    },
    "http": {
        RawPacket: RawPacket.fetch_from_global
    }
}

def _generate_filter_structure(filters: list[str], proto:str, glob:dict, local:dict):
    if proto not in type_annotations_associations.keys():
        raise Exception("Invalid protocol")
    
    res = []
    
    valid_annotation_type = type_annotations_associations[proto]
    def add_func_to_list(func):
        if not callable(func):
            raise Exception(f"{func} is not a function")
        sig = signature(func)
        params_function = []
        
        for k, v in sig.parameters.items():
            if v.annotation in valid_annotation_type.keys():
                params_function.append((v.annotation, valid_annotation_type[v.annotation]))
            else:
                raise Exception(f"Invalid type annotation {v.annotation} for function {func.__name__}")
        res.append((func, params_function))
    
    for filter in filters:
        if not isinstance(filter, str):
            raise Exception("Invalid filter list: must be a list of strings")
        if filter in glob.keys():
            add_func_to_list(glob[filter])
        elif filter in local.keys():
            add_func_to_list(local[filter])
        else:
            raise Exception(f"Filter {filter} not found")
    
    return res

def get_filters_info(code:str, proto:str):
    glob = {}
    local = {}
    exec(code, glob, local)
    exec("import firegex.nfproxy", glob, local)
    filters = eval("firegex.nfproxy.get_pyfilters()", glob, local)
    return _generate_filter_structure(filters, proto, glob, local)

def get_filter_names(code:str, proto:str):
    return [ele[0].__name__ for ele in get_filters_info(code, proto)]    

def compile():
    glob = globals()
    local = locals()
    filters = glob["__firegex_pyfilter_enabled"]
    proto = glob["__firegex_proto"]
    glob["__firegex_func_list"] = _generate_filter_structure(filters, proto, glob, local)
    glob["__firegex_stream"] = []
    glob["__firegex_stream_size"] = 0
    
    if "FGEX_STREAM_MAX_SIZE" in local and int(local["FGEX_STREAM_MAX_SIZE"]) > 0:
        glob["__firegex_stream_max_size"] = int(local["FGEX_STREAM_MAX_SIZE"])
    elif "FGEX_STREAM_MAX_SIZE" in glob and int(glob["FGEX_STREAM_MAX_SIZE"]) > 0:
        glob["__firegex_stream_max_size"] = int(glob["FGEX_STREAM_MAX_SIZE"])
    else:
        glob["__firegex_stream_max_size"] = 1*8e20 # 1MB default value
    
    if "FGEX_FULL_STREAM_ACTION" in local and local["FGEX_FULL_STREAM_ACTION"] in FULL_STREAM_ACTIONS:
        glob["__firegex_full_stream_action"] = local["FGEX_FULL_STREAM_ACTION"]
    else:
        glob["__firegex_full_stream_action"] = "flush"
    
    glob["__firegex_pyfilter_result"] = None

def handle_packet():
    glob = globals()
    func_list = glob["__firegex_func_list"]
    final_result = ACCEPT
    cache_call = {}
    cache_call[RawPacket] = RawPacket.fetch_from_global()
    data_size = len(cache_call[RawPacket].data)
    if glob["__firegex_stream_size"]+data_size > glob["__firegex_stream_max_size"]:
        match glob["__firegex_full_stream_action"]:
            case "flush":
                glob["__firegex_stream"] = []
                glob["__firegex_stream_size"] = 0
            case "accept":
                glob["__firegex_pyfilter_result"] = {
                    "action": ACCEPT,
                    "matched_by": None,
                    "mangled_packet": None
                }
                return
            case "reject":
                glob["__firegex_pyfilter_result"] = {
                    "action": REJECT,
                    "matched_by": "@MAX_STREAM_SIZE_REACHED",
                    "mangled_packet": None
                }
                return
            case "drop":
                glob["__firegex_pyfilter_result"] = {
                    "action": DROP,
                    "matched_by": "@MAX_STREAM_SIZE_REACHED",
                    "mangled_packet": None
                }
                return
    glob["__firegex_stream"].append(cache_call[RawPacket])
    glob["__firegex_stream_size"] += data_size
    func_name = None
    mangled_packet = None
    for filter in func_list:
        final_params = []
        for ele in filter[1]:
            if ele[0] not in cache_call.keys():
                try:
                    cache_call[ele[0]] = ele[1]()
                except NotReadyToRun:
                    cache_call[ele[0]] = None
            if cache_call[ele[0]] is None:
                continue # Parsing raised NotReadyToRun, skip filter
            final_params.append(cache_call[ele[0]])
        res = filter[0](*final_params)
        if res is None:
            continue #ACCEPTED
        if res == MANGLE:
            if RawPacket not in cache_call.keys():
                continue #Packet not modified
            pkt:RawPacket = cache_call[RawPacket]
            mangled_packet = pkt.raw_packet
            break
        elif res != ACCEPT:
            final_result = res
            func_name = filter[0].__name__
            break
    glob["__firegex_pyfilter_result"] = {
        "action": final_result,
        "matched_by": func_name,
        "mangled_packet": mangled_packet
    }

