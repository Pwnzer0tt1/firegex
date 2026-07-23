import { Button, Card, Group, Image, Loader, LoadingOverlay, Notification, Space, Stack, PasswordInput, Title, Text, Code, ThemeIcon, Box } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useEffect, useState } from 'react';
import { ImCross } from 'react-icons/im';
import { MdCloudOff } from 'react-icons/md';
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

const AuthShell = ({ children }: { children: React.ReactNode }) => (
  <Box style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "40px 20px" }}>
    <Card withBorder radius="lg" p="xl" shadow="md" style={{ width: "100%", maxWidth: 440, borderColor: 'var(--fourth_color)', backgroundColor: 'var(--third_color)', boxShadow: '0 8px 32px rgba(0,0,0,0.3)' }}>
      <Stack align="center" gap={2} mb="lg">
        <Image src="/header-logo.png" alt="Firegex logo" w={56} />
        <Title order={2} ta="center" style={{ fontFamily: 'Hanken Grotesk', color: 'var(--accent-color)' }}>[Fi]*regex</Title>
      </Stack>
      {children}
    </Card>
  </Box>
)

const StatusCard = ({ title, description, color, children }: { title: string, description: string, color: string, children?: React.ReactNode }) => (
  <Box style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "40px 20px" }}>
    <Card withBorder radius="lg" p="xl" shadow="md" style={{ width: "100%", maxWidth: 480, borderColor: 'var(--fourth_color)', backgroundColor: 'var(--third_color)', boxShadow: '0 8px 32px rgba(0,0,0,0.3)' }}>
      <Stack align="center" gap="md">
        <ThemeIcon size={64} radius="xl" color={color} variant="light">
          <MdCloudOff size={32} />
        </ThemeIcon>
        <Title order={2} ta="center">{title}</Title>
        <Text c="dimmed" ta="center">{description}</Text>
        {children}
      </Stack>
    </Card>
  </Box>
)

function App() {

  const [loading, setLoading] = useState(true);
  const [systemStatus, setSystemStatus] = useState<ServerStatusResponse>({ status: "", loggined: false })
  const [reqError, setReqError] = useState<undefined | string>()
  const [error, setError] = useState<string | null>()
  const [loadinBtn, setLoadingBtn] = useState(false);
  const queryClient = useQueryClient()
  const { access_token } = useAuthStore()

  useEffect(() => {
    socketio.auth = { token: access_token || "" }
    socketio.connect()
    getStatus()
    socketio.on("update", (data) => {
      queryClient.invalidateQueries({ queryKey: data })
    })
    socketio.on("connect_error", (err) => {
      if (access_token) {
        errorNotify("Socket.Io connection failed! ", `Error message: [${err.message}]`)
      }
      getStatus()
    });
    return () => {
      socketio.off("update")
      socketio.off("connect_error")
      socketio.disconnect()
    }
  }, [access_token])

  const getStatus = () => {
    getstatus().then(res => {
      setSystemStatus(res)
      setReqError(undefined)
    }).catch(err => {
      setReqError(err.toString())
      setTimeout(getStatus, 500)
    }).finally(() => setLoading(false))
  }

  useEffect(() => {
    getStatus()
  }, [])

  const form = useForm({
    initialValues: {
      password: "",
    },
    validate: {
      password: (value) => value !== "" ? null : "Password is required",
    }
  })

  if (loading) {
    return <LoadingOverlay visible />
  } else if (reqError) {
    return <StatusCard title="Can't reach Firegex 🔥" description="The backend isn't responding. Retrying automatically..." color="red">
      <Code block style={{ width: "100%", wordBreak: "break-word", backgroundColor: 'var(--secondary_color)' }}>{reqError}</Code>
      <Loader size="sm" />
    </StatusCard>
  } else if (systemStatus.status === "init") {

    const submitRequest = async (values: PasswordSend) => {
      setLoadingBtn(true)
      await setpassword(values).then(res => {
        if (!res) {
          setSystemStatus({ loggined: true, status: "run" })
        } else {
          setError(res)
        }
      }).catch(err => setError(err.toString()))
      setLoadingBtn(false)
      form.reset()
    }


    return <AuthShell>
      <Title order={5} ta="center" style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>Choose the password for access to the firewall 🔒</Title>
      <Space h="xl" />
      <form onSubmit={form.onSubmit(submitRequest)} style={{ width: "100%" }}>
        <PasswordInput
          label="Password"
          placeholder="$3cr3t"
          {...form.getInputProps('password')}
        />
        <Group mt="xl">
          <Button loading={loadinBtn} type="submit" variant="light" color="cyan" fullWidth>Set Password</Button>
        </Group>
      </form>
      {error && <>
        <Space h="lg" />
        <Notification icon={<ImCross size={14} />} color="red" onClose={() => { setError(null) }}>
          Error: {error}
        </Notification></>}
    </AuthShell>
  } else if (systemStatus.status === "run" && !systemStatus.loggined) {
    const submitRequest = async (values: PasswordSend) => {
      setLoadingBtn(true)
      await login(values).then(res => {
        if (!res) {
          queryClient.invalidateQueries()
          setSystemStatus({ ...systemStatus, loggined: true })
        } else {
          setError("Login failed")
        }
      }).catch(err => setError(err.toString()))
      setLoadingBtn(false)
      form.reset()
    }


    return <AuthShell>
      <Title order={5} ta="center" style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>Insert the password to unlock the firewall 🔒</Title>
      <Space h="xl" />
      <form onSubmit={form.onSubmit(submitRequest)} style={{ width: "100%" }}>
        <PasswordInput
          label="Password"
          placeholder="$3cr3t"
          {...form.getInputProps('password')}
        />
        <Group mt="xl">
          <Button loading={loadinBtn} type="submit" variant="light" color="cyan" fullWidth>Login</Button>
        </Group>
      </form>
      {error && <>
        <Space h="lg" />
        <Notification icon={<ImCross size={14} />} color="red" onClose={() => { setError(null) }}>
          Error: {error}
        </Notification></>}
    </AuthShell>
  } else if (systemStatus.status === "run" && systemStatus.loggined) {
    return <PageRouting getStatus={getStatus} />
  } else {
    return <StatusCard title="Unexpected error 🔥" description="Firegex returned an unexpected status. Try reloading the page." color="orange" />
  }
}

import TLSDecrypt from './pages/TLSDecrypt';

const PageRouting = ({ getStatus }: { getStatus: () => void }) => {

  return <Routes>
    <Route element={<MainLayout><Outlet /></MainLayout>}>
      <Route path="tls-decrypt" element={<TLSDecrypt />} />
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
