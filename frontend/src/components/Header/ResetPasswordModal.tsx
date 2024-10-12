import { Button, Group, Modal, Notification, PasswordInput, Space, Switch } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useState } from "react"
import { ImCross } from "react-icons/im";
import { ChangePassword } from "../../js/models";
import { changepassword, okNotify } from "../../js/utils";

function ResetPasswordModal({ opened, onClose }:{ opened: boolean, onClose: () => void }) {
    const form = useForm({
        initialValues: {
            password:"",
            expire:true
        },
        validate:{
          password: (value) => value !== ""? null : "Password is required"
        }
      })
      const [loadingBtn, setLoadingBtn] = useState(false)
      const [error, setError] = useState<null|string>(null)

      const submitRequest = async (values:ChangePassword) => {
        setLoadingBtn(true)
        await changepassword(values).then(res => {
          if(!res){
            okNotify("Password change done!","The password of the firewall has been changed!")
            onClose()
            form.reset()
          }else{
            setError(res)
          }
        }).catch( err => setError(err.toString()))
        setLoadingBtn(false)
      }
      return <Modal size="xl" title="Change Firewall Password" opened={opened} onClose={onClose} closeOnClickOutside={false} centered>

      <form onSubmit={form.onSubmit(submitRequest)}>
          <Space h="md" />
          <PasswordInput
              label="New Password"
              placeholder="$3cr3t"
              {...form.getInputProps('password')}
          />
          <Space h="md" />
          <Switch
              label="Expire the login status to all connections"
              {...form.getInputProps('expire', { type: 'checkbox' })}
          />
          <Space h="md" />
          <Group align="right" mt="md">
            <Button loading={loadingBtn} type="submit">Change Password</Button>
          </Group>
        </form>
        <Space h="xl" />
        {error?<>
          <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
              Error: {error}
          </Notification><Space h="md" /></>:null}
    </Modal>

}

export default ResetPasswordModal;
