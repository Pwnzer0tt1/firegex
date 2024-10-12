import { Button, Group, Modal, Notification, Space, Switch, Text } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useState } from "react"
import { ImCross } from "react-icons/im";
import { okNotify, resetfiregex } from "../../js/utils";

function ResetModal({ opened, onClose }:{ opened: boolean, onClose: () => void }) {
    const form = useForm({
        initialValues: {
            delete_data:false,
        }
      })

      const [loadingBtn, setLoadingBtn] = useState(false)
      const [error, setError] = useState<null|string>(null)

      const close = () => {
        setError(null)
        setLoadingBtn(false)
        form.reset()
        onClose()
      }

      const submitRequest = async ({ delete_data }:{ delete_data:boolean }) => {
        setLoadingBtn(true)
        await resetfiregex(delete_data).then(res => {
          if(!res){
            okNotify("Firegex Resetted!","Firegex has been resetted!")
            setError(null);
            close()
            form.reset()
          }else{
            setError(res)
          }
        }).catch( err => setError(err.toString()))
        setLoadingBtn(false)
      }
      return <Modal size="xl" title="Reset Firegex" opened={opened} onClose={close} closeOnClickOutside={false} centered>
      <b>Resetting firegex will trigger the reloading of the firewall rules in nftables and the restarting
      of all services filters</b> (technically the c++ filter processes).<br />
      This will only cause the stop of the filters for a second and then restore them, during this time the services will continue to be available without interruptions.<br />
      <b><Text color="red">Enabling the option below you will totaly reset firegex like you started it for the first time.</Text></b>
      <form onSubmit={form.onSubmit(submitRequest)}>
          <Space h="md" />
          <Switch
              label="Delete all data, including the firewall rules"
              {...form.getInputProps('delete_data', { type: 'checkbox' })}
          />
          <Space h="md" />
          <Group align="right" mt="md">
            <Button loading={loadingBtn} onClick={close} >Cancel</Button>
            <Button loading={loadingBtn} type="submit" color="red">Reset</Button>
          </Group>
        </form>
        <Space h="xl" />
        {error?<>
          <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
              Error: {error}
          </Notification><Space h="md" /></>:null}
    </Modal>

}

export default ResetModal;
