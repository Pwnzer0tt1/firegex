import { IoIosWarning } from "react-icons/io"
import { socketio, WARNING_NFPROXY_TIME_LIMIT } from "../../js/utils"
import { Tooltip } from "@mantine/core"
import { useEffect, useState } from "react"
import { round } from "@mantine/core/lib/components/ColorPicker/converters/parsers"


export const ExceptionWarning = ({ service_id }: { service_id: string }) => {
    const [lastExceptionTimestamp, setLastExceptionTimestamp] = useState<number>(0)

    useEffect(() => {
        socketio.emit("nfproxy-exception-join", { service: service_id });
        socketio.on(`nfproxy-exception-${service_id}`, (data) => {
            setLastExceptionTimestamp(data)
        });
        return () => {
            socketio.emit("nfproxy-exception-leave", { service: service_id });
        }
    }, [])

    const [_time, setTime] = useState(new Date());

    useEffect(() => {
      const interval = setInterval(() => {
        setTime(new Date());
      }, 1000);
  
      return () => clearInterval(interval);
    }, []);
  
    const deltaTime = new Date().getTime()-lastExceptionTimestamp
    const minutes = Math.floor(deltaTime/(1000*60))
    const seconds = Math.floor(deltaTime/1000)%60

    const deltaStringTime = `${minutes.toString().length>1?minutes:"0"+minutes}:${seconds.toString().length>1?seconds:"0"+seconds}`

    return <>
        {(new Date().getTime()-lastExceptionTimestamp <= WARNING_NFPROXY_TIME_LIMIT)?
            <Tooltip label={`There was an exception less than ${deltaStringTime} minutes ago: check the logs`} color="yellow">
                <IoIosWarning size={30} style={{ color: "yellow" }} />
            </Tooltip>
        :null}
    </>
}