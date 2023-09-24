import { Button, Group, Loader, LoadingOverlay, Notification, Space, PasswordInput, Title } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useEffect, useState } from 'react';
import { ImCross } from 'react-icons/im';
import { Outlet, Route, Routes } from 'react-router-dom';
import MainLayout from './components/MainLayout';
import { PasswordSend, ServerStatusResponse } from './js/models';
import { DEV_IP_BACKEND, errorNotify, fireUpdateRequest, getstatus, HomeRedirector, IS_DEV, login, setpassword } from './js/utils';
import NFRegex from './pages/NFRegex';
import io from 'socket.io-client';
import RegexProxy from './pages/RegexProxy';
import ServiceDetailsNFRegex from './pages/NFRegex/ServiceDetails';
import ServiceDetailsProxyRegex from './pages/RegexProxy/ServiceDetails';
import PortHijack from './pages/PortHijack';
import { Firewall } from './pages/Firewall';


const socket = IS_DEV?io("ws://"+DEV_IP_BACKEND, {transports: ["websocket", "polling"], path:"/sock" }):io({transports: ["websocket", "polling"], path:"/sock"});

function App() {

  const [loading, setLoading] = useState(true);
  const [systemStatus, setSystemStatus] = useState<ServerStatusResponse>({status:"", loggined:false})
  const [reqError, setReqError] = useState<undefined|string>()
  const [error, setError] = useState<string|null>()
  const [loadinBtn, setLoadingBtn] = useState(false);

  const getStatus = () =>{
      getstatus().then( res =>{
        setSystemStatus(res)
        setReqError(undefined)
        setLoading(false)
      }).catch(err=>{
        setReqError(err.toString())
        setLoading(false)
        setTimeout(getStatus, 500)
      })
  }

  useEffect(()=>{
    getStatus()
    socket.on("update", () => {
      fireUpdateRequest()
    })
    socket.on("connect_error", (err) => {
      errorNotify("Socket.Io connection failed! ",`Error message: [${err.message}]`)
      getStatus()
    });
    return () => {
      socket.off("update")
      socket.off("connect_error")
    }
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
    return <div className='center-flex-row' style={{padding:"100px"}}>
      <Title order={1} align="center">Error launching Firegex! 🔥</Title>
      <Space h="md" />
      <Title order={4} align="center">Error communicating with backend</Title>
      <Space h="md" />
      Errore: {reqError}
      <Space h="xl" />
      <Loader />
    </div>
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
    }
    

    return <div className='center-flex-row' style={{padding:"100px"}}>
      <Title order={3} align="center">Setup: Choose the password for access to the firewall 🔒</Title>
      <Space h="xl" />
      <form onSubmit={form.onSubmit(submitRequest)} style={{width:"80%"}}>
          <PasswordInput
              label="Password"
              placeholder="$3cr3t"
              {...form.getInputProps('password')}
          />
          <Group position="right" mt="md">
            <Button loading={loadinBtn} type="submit">Set Password</Button>
          </Group>
        </form>
        <Space h="xl" />
        {error?<>
          <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
              Error: {error}
          </Notification><Space h="md" /></>:null}
    </div>
  }else if (systemStatus.status === "run" && !systemStatus.loggined){
    const submitRequest = async (values:PasswordSend) => {
        setLoadingBtn(true)
        await login(values).then(res => {
          if(!res){
            setSystemStatus({...systemStatus, loggined:true})
          }else{
            setError("Login failed")
          }
        }).catch( err => setError(err.toString()))
        setLoadingBtn(false)
      }
    

    return <div className='center-flex-row' style={{padding:"100px"}}>
      <Title order={2} align="center">Welcome to Firegex 🔥</Title>
      <Space h="xl" />
      <Title order={2} align="center">Before you use the firewall, insert the password 🔒</Title>
      <Space h="xl" />
      <form onSubmit={form.onSubmit(submitRequest)} style={{width:"80%"}}>
          <PasswordInput
              label="Password"
              placeholder="$3cr3t"
              {...form.getInputProps('password')}
          />
          <Group position="right" mt="md">
            <Button loading={loadinBtn} type="submit">Login</Button>
          </Group>
        </form>
        <Space h="xl" />
        {error?<>
          <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
              Error: {error}
          </Notification><Space h="md" /></>:null}
    </div>
  }else if (systemStatus.status === "run" && systemStatus.loggined){
    return <Routes>
              <Route element={<MainLayout><Outlet /></MainLayout>}>
                  <Route path="nfregex" element={<NFRegex><Outlet /></NFRegex>} >
                    <Route path=":srv" element={<ServiceDetailsNFRegex />} />
                  </Route>
                  <Route path="regexproxy" element={<RegexProxy><Outlet /></RegexProxy>} >
                    <Route path=":srv" element={<ServiceDetailsProxyRegex />} />
                  </Route>
                  <Route path="firewall" element={<Firewall />} />
                  <Route path="porthijack" element={<PortHijack />} />
                <Route path="*" element={<HomeRedirector />} />
              </Route>
          </Routes>
  }else{
    return <div className='center-flex-row' style={{padding:"100px"}}>
      <Title order={1} align="center">Error launching Firegex! 🔥</Title>
      <Space h="md" />
      <Title order={4} align="center">Error communicating with backend</Title>
    </div>
  }
}

export default App;
