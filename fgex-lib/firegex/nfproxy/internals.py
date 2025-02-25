from inspect import signature
from firegex.nfproxy.params import RawPacket, NotReadyToRun
from firegex.nfproxy import Action, FullStreamAction
from dataclasses import dataclass, field

type_annotations_associations = {
    "tcp": {
        RawPacket: RawPacket.fetch_from_global
    },
    "http": {
        RawPacket: RawPacket.fetch_from_global
    }
}

@dataclass
class FilterHandler:
    func: callable
    name: str
    params: dict[type, callable]
    proto: str

class internal_data:
    filter_call_info: list[FilterHandler] = []
    stream: list[RawPacket] = []
    stream_size: int = 0
    stream_max_size: int = 1*8e20
    full_stream_action: str = "flush"
    filter_glob: dict = {}

@dataclass
class PacketHandlerResult:
    glob: dict = field(repr=False)
    action: Action = Action.ACCEPT
    matched_by: str = None
    mangled_packet: bytes = None        
    
    def set_result(self) -> None:
        self.glob["__firegex_pyfilter_result"] = {
            "action": self.action.value,
            "matched_by": self.matched_by,
            "mangled_packet": self.mangled_packet
        }
    
    def reset_result(self) -> None:
        self.glob["__firegex_pyfilter_result"] = None

def context_call(func, *args, **kargs):
    internal_data.filter_glob["__firegex_tmp_args"] = args
    internal_data.filter_glob["__firegex_tmp_kargs"] = kargs
    internal_data.filter_glob["__firege_tmp_call"] = func
    res = eval("__firege_tmp_call(*__firegex_tmp_args, **__firegex_tmp_kargs)", internal_data.filter_glob, internal_data.filter_glob)
    del internal_data.filter_glob["__firegex_tmp_args"]
    del internal_data.filter_glob["__firegex_tmp_kargs"]
    del internal_data.filter_glob["__firege_tmp_call"]
    return res

def generate_filter_structure(filters: list[str], proto:str, glob:dict) -> list[FilterHandler]:
    if proto not in type_annotations_associations.keys():
        raise Exception("Invalid protocol")
    res = []
    valid_annotation_type = type_annotations_associations[proto]
    def add_func_to_list(func):
        if not callable(func):
            raise Exception(f"{func} is not a function")
        sig = signature(func)
        params_function = {}
        
        for k, v in sig.parameters.items():
            if v.annotation in valid_annotation_type.keys():
                params_function[v.annotation] = valid_annotation_type[v.annotation]
            else:
                raise Exception(f"Invalid type annotation {v.annotation} for function {func.__name__}")
        
        res.append(
            FilterHandler(
                func=func,
                name=func.__name__,
                params=params_function,
                proto=proto
            )
        )
    
    for filter in filters:
        if not isinstance(filter, str):
            raise Exception("Invalid filter list: must be a list of strings")
        if filter in glob.keys():
            add_func_to_list(glob[filter])
        else:
            raise Exception(f"Filter {filter} not found")
    return res

def get_filters_info(code:str, proto:str) -> list[FilterHandler]:
    glob = {}
    exec(code, glob, glob)
    exec("import firegex.nfproxy", glob, glob)
    filters = eval("firegex.nfproxy.get_pyfilters()", glob, glob)
    try:
        return generate_filter_structure(filters, proto, glob)
    finally:
        exec("firegex.nfproxy.clear_pyfilter_registry()", glob, glob)
        

def get_filter_names(code:str, proto:str) -> list[str]:
    return [ele.name for ele in get_filters_info(code, proto)]    

def handle_packet() -> None:
    cache_call = {} # Cache of the data handler calls
    
    pkt_info = RawPacket.fetch_from_global(internal_data.filter_glob)
    cache_call[RawPacket] = pkt_info
    
    final_result = Action.ACCEPT
    data_size = len(pkt_info.data)
    
    result = PacketHandlerResult(internal_data.filter_glob)
    
    if internal_data.stream_size+data_size > internal_data.stream_max_size:
        match internal_data.full_stream_action:
            case FullStreamAction.FLUSH:
                internal_data.stream = []
                internal_data.stream_size = 0
            case FullStreamAction.ACCEPT:
                result.action = Action.ACCEPT
                return result.set_result()
            case FullStreamAction.REJECT:
                result.action = Action.REJECT
                result.matched_by = "@MAX_STREAM_SIZE_REACHED"
                return result.set_result()
            case FullStreamAction.REJECT:
                result.action = Action.DROP
                result.matched_by = "@MAX_STREAM_SIZE_REACHED"
                return result.set_result()
    
    internal_data.stream.append(pkt_info)
    internal_data.stream_size += data_size
    
    func_name = None
    mangled_packet = None
    for filter in internal_data.filter_call_info:
        final_params = []
        for data_type, data_func in filter.params.items():
            if data_type not in cache_call.keys():
                try:
                    cache_call[data_type] = data_func(internal_data.filter_glob)
                except NotReadyToRun:
                    cache_call[data_type] = None
            if cache_call[data_type] is None:
                continue # Parsing raised NotReadyToRun, skip filter
            final_params.append(cache_call[data_type])
        
        res = context_call(filter.func, *final_params)
        
        if res is None:
            continue #ACCEPTED
        if not isinstance(res, Action):
            raise Exception(f"Invalid return type {type(res)} for function {filter.name}")
        if res == Action.MANGLE:
            mangled_packet = pkt_info.raw_packet
        if res != Action.ACCEPT:
            func_name = filter.name
            final_result = res
            break
    
    result.action = final_result
    result.matched_by = func_name
    result.mangled_packet = mangled_packet
    
    return result.set_result()


def compile(glob:dict) -> None:    
    internal_data.filter_glob = glob
    
    filters = glob["__firegex_pyfilter_enabled"]
    proto = glob["__firegex_proto"]
    
    internal_data.filter_call_info = generate_filter_structure(filters, proto, glob)

    if "FGEX_STREAM_MAX_SIZE" in glob and int(glob["FGEX_STREAM_MAX_SIZE"]) > 0:
        internal_data.stream_max_size = int(glob["FGEX_STREAM_MAX_SIZE"])
    else:
        internal_data.stream_max_size = 1*8e20 # 1MB default value
    
    if "FGEX_FULL_STREAM_ACTION" in glob and isinstance(glob["FGEX_FULL_STREAM_ACTION"], FullStreamAction):
        internal_data.full_stream_action = glob["FGEX_FULL_STREAM_ACTION"]
    else:
        internal_data.full_stream_action = FullStreamAction.FLUSH
    
    PacketHandlerResult(glob).reset_result()
