import { Button, Group, Loader, LoadingOverlay, Notification, Space, PasswordInput, Title, Box } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useEffect, useState } from 'react';
import { ImCross } from 'react-icons/im';
import { Outlet, Route, Routes } from 'react-router';
import MainLayout from './components/MainLayout';
import { PasswordSend, ServerStatusResponse } from './js/models';
import { errorNotify, getstatus, HomeRedirector, IS_DEV, login, setpassword, socketio } from './js/utils';
import NFRegex from './pages/NFRegex';
import ServiceDetailsNFRegex from './pages/NFRegex/ServiceDetails';
import PortHijack from './pages/PortHijack';
import { Firewall } from './pages/Firewall';
import { useQueryClient } from '@tanstack/react-query';
import NFProxy from './pages/NFProxy';
import ServiceDetailsNFProxy from './pages/NFProxy/ServiceDetails';
import { useAuthStore } from './js/store';

function App() {

  const [loading, setLoading] = useState(true);
  const [systemStatus, setSystemStatus] = useState<ServerStatusResponse>({status:"", loggined:false})
  const [reqError, setReqError] = useState<undefined|string>()
  const [error, setError] = useState<string|null>()
  const [loadinBtn, setLoadingBtn] = useState(false);
  const queryClient = useQueryClient()
  const { access_token } = useAuthStore()

  useEffect(()=>{
    socketio.auth = { token: access_token || "" }
    socketio.connect()
    getStatus()
    socketio.on("update", (data) => {
      queryClient.invalidateQueries({ queryKey: data  })
    })
    socketio.on("connect_error", (err) => {
      if (access_token){
        errorNotify("Socket.Io connection failed! ",`Error message: [${err.message}]`)
      }
      getStatus()
    });
  return () => {
    socketio.off("update")
    socketio.off("connect_error")
    socketio.disconnect()
  }
  },[access_token])

  const getStatus = () =>{
    getstatus().then( res =>{
      setSystemStatus(res)
      setReqError(undefined)
    }).catch(err=>{
      setReqError(err.toString())
      setTimeout(getStatus, 500)
    }).finally( ()=>setLoading(false) )
  }

  useEffect(()=>{
    getStatus()
  },[])

  const form = useForm({
    initialValues: {
        password:"",
    },
    validate:{
      password: (value) => value !== "" ? null : "Password is required",
    }
  })

  if (loading){
    return <LoadingOverlay visible/>
  }else if (reqError){
    return <Box className='center-flex-row' style={{padding:"100px"}}>
      <Title order={1} style={{textAlign:"center"}}>Error launching Firegex! 🔥</Title>
      <Space h="md" />
      <Title order={4} style={{textAlign:"center"}}>Error communicating with backend</Title>
      <Space h="md" />
      Error: {reqError}
      <Space h="xl" />
      <Loader />
    </Box>
  }else if (systemStatus.status === "init"){
    
    const submitRequest = async (values:PasswordSend) => {
      setLoadingBtn(true)
      await setpassword(values).then(res => {
        if(!res){
          setSystemStatus({loggined:true, status:"run"})
        }else{
          setError(res)
        }
      }).catch( err => setError(err.toString()))
      setLoadingBtn(false)
      form.reset()
    }
    

    return <Box className='center-flex-row' style={{padding:"100px"}}>
      <Title order={3} style={{textAlign:"center"}}>Setup: Choose the password for access to the firewall 🔒</Title>
      <Space h="xl" />
      <form onSubmit={form.onSubmit(submitRequest)} style={{width:"80%"}}>
          <PasswordInput
              label="Password"
              placeholder="$3cr3t"
              {...form.getInputProps('password')}
          />
          <Group align="right" mt="md">
            <Button loading={loadinBtn} type="submit">Set Password</Button>
          </Group>
        </form>
        <Space h="xl" />
        {error?<>
          <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
              Error: {error}
          </Notification><Space h="md" /></>:null}
    </Box>
  }else if (systemStatus.status === "run" && !systemStatus.loggined){
    const submitRequest = async (values:PasswordSend) => {
        setLoadingBtn(true)
        await login(values).then(res => {
          if(!res){
            queryClient.invalidateQueries()
            setSystemStatus({...systemStatus, loggined:true})
          }else{
            setError("Login failed")
          }
        }).catch( err => setError(err.toString()))
        setLoadingBtn(false)
        form.reset()
      }
    

    return <Box className='center-flex-row' style={{padding:"100px"}}>
      <Title order={2} style={{textAlign:"center"}}>Welcome to Firegex 🔥</Title>
      <Space h="xl" />
      <Title order={2} style={{textAlign:"center"}}>Before you use the firewall, insert the password 🔒</Title>
      <Space h="xl" />
      <form onSubmit={form.onSubmit(submitRequest)} style={{width:"80%"}}>
          <PasswordInput
              label="Password"
              placeholder="$3cr3t"
              {...form.getInputProps('password')}
          />
          <Group align="right" mt="md">
            <Button loading={loadinBtn} type="submit">Login</Button>
          </Group>
        </form>
        <Space h="xl" />
        {error?<>
          <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
              Error: {error}
          </Notification><Space h="md" /></>:null}
    </Box>
  }else if (systemStatus.status === "run" && systemStatus.loggined){
    return <PageRouting getStatus={getStatus} />
  }else{
    return <Box className='center-flex-row' style={{padding:"100px"}}>
      <Title order={1} style={{textAlign:"center"}}>Error launching Firegex! 🔥</Title>
      <Space h="md" />
      <Title order={4} style={{textAlign:"center"}}>Error communicating with backend</Title>
    </Box>
  }
}

const PageRouting = ({ getStatus }:{ getStatus:()=>void }) => {

  return <Routes>
  <Route element={<MainLayout><Outlet /></MainLayout>}>
      <Route path="nfregex" element={<NFRegex><Outlet /></NFRegex>} >
        <Route path=":srv" element={<ServiceDetailsNFRegex />} />
      </Route>
      <Route path="nfproxy" element={<NFProxy><Outlet /></NFProxy>} >
        <Route path=":srv" element={<ServiceDetailsNFProxy />} />
      </Route>
      <Route path="firewall" element={<Firewall />} />
      <Route path="porthijack" element={<PortHijack />} />
    <Route path="*" element={<HomeRedirector />} />
  </Route>
</Routes>
}



export default App;
