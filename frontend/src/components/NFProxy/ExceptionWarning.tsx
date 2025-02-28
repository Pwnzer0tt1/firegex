import { IoIosWarning } from "react-icons/io"
import { socketio, WARNING_NFPROXY_TIME_LIMIT } from "../../js/utils"
import { Tooltip } from "@mantine/core"
import { useEffect, useState } from "react"


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

    return <>
        {(new Date().getTime()-lastExceptionTimestamp <= WARNING_NFPROXY_TIME_LIMIT)?
            <Tooltip label={`There was an exception less than ${WARNING_NFPROXY_TIME_LIMIT/(1000*60)} minutes ago: check the logs`} color="yellow">
                <IoIosWarning size={30} style={{ color: "yellow" }} />
            </Tooltip>
        :null}
    </>
}