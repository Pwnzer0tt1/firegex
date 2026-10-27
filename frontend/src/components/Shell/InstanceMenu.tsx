import { ActionIcon, Menu, Tooltip } from '@mantine/core'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { FaLock, FaUnlockAlt } from 'react-icons/fa'
import { ImExit } from 'react-icons/im'
import { MdDownload, MdOutlineSettingsBackupRestore, MdUpload } from 'react-icons/md'
import { TbSettings } from 'react-icons/tb'
import { useAuthStore, useSystemStore } from '../../js/store'
import { errorNotify, getapi, logout, okNotify, postapi } from '../../js/utils'
import AuthModeModal from './AuthModeModal'
import ResetModal from './ResetModal'
import ResetPasswordModal from './ResetPasswordModal'

/** Download the whole configuration as one JSON file, dated so two never collide. */
async function exportBackup() {
    try {
        const data = await getapi('export')
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })
        const url = URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.href = url
        a.download = `firegex_backup_${new Date().toISOString().split('T')[0]}.json`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
        okNotify("Backup exported", "Your configuration backup has been downloaded.")
    } catch (err) {
        errorNotify("Export failed", `${err}`)
    }
}

/** Ask for a backup file and restore it. The server loads it all or nothing. */
function importBackup(onDone: () => void) {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.json'
    input.onchange = (e) => {
        const file = (e.target as HTMLInputElement).files?.[0]
        if (!file) return
        const reader = new FileReader()
        reader.onload = (loaded) => {
            let data: unknown
            try {
                data = JSON.parse(loaded.target?.result as string)
            } catch (err) {
                errorNotify("Invalid JSON", `${err}`)
                return
            }
            postapi('import', data).then(() => {
                okNotify("Backup imported", "Configuration has been restored successfully.")
                onDone()
            }).catch(err => errorNotify("Import failed", `${err}`))
        }
        reader.readAsText(file)
    }
    input.click()
}

/**
 * Everything about the instance rather than one service: access, backups, reset.
 *
 * These are reached for a few times a competition, so they live behind one button in
 * the sidebar's footer instead of taking a header across every page.
 */
export default function InstanceMenu() {
    const queryClient = useQueryClient()
    const { authDisabled } = useSystemStore()
    // A session from before authentication was turned off is what lets this browser put
    // it back; without one the host is the only way, and offering the item would lie.
    const { access_token } = useAuthStore()
    const [passwordOpen, setPasswordOpen] = useState(false)
    const [authModeOpen, setAuthModeOpen] = useState(false)
    const [resetOpen, setResetOpen] = useState(false)

    const doLogout = () => logout()
        .then(() => window.location.reload())
        .catch(err => errorNotify("Logout failed", `${err}`))

    return <>
        <Menu position="top-end" withArrow width={240}>
            <Menu.Target>
                <Tooltip label="Instance settings" position="top">
                    <ActionIcon variant="subtle" color="gray" size="lg" aria-label="Instance settings">
                        <TbSettings size={18} />
                    </ActionIcon>
                </Tooltip>
            </Menu.Target>
            <Menu.Dropdown>
                {!authDisabled && <>
                    <Menu.Label>Access</Menu.Label>
                    <Menu.Item leftSection={<FaLock size={13} />} onClick={() => setPasswordOpen(true)}>
                        Change password
                    </Menu.Item>
                    <Menu.Item color="red" leftSection={<FaUnlockAlt size={13} />} onClick={() => setAuthModeOpen(true)}>
                        Turn authentication off
                    </Menu.Item>
                    <Menu.Divider />
                </>}
                {authDisabled && access_token && <>
                    <Menu.Label>Access</Menu.Label>
                    <Menu.Item color="green" leftSection={<FaLock size={13} />} onClick={() => setAuthModeOpen(true)}>
                        Turn authentication on
                    </Menu.Item>
                    <Menu.Divider />
                </>}
                <Menu.Label>Backup</Menu.Label>
                <Menu.Item leftSection={<MdDownload size={16} />} onClick={exportBackup}>Export backup</Menu.Item>
                <Menu.Item leftSection={<MdUpload size={16} />}
                    onClick={() => importBackup(() => queryClient.invalidateQueries())}>Import backup</Menu.Item>
                <Menu.Divider />
                <Menu.Item color="red" leftSection={<MdOutlineSettingsBackupRestore size={16} />}
                    onClick={() => setResetOpen(true)}>Reset firegex</Menu.Item>
                {!authDisabled && <Menu.Item leftSection={<ImExit size={14} />} onClick={doLogout}>Log out</Menu.Item>}
            </Menu.Dropdown>
        </Menu>
        <ResetPasswordModal opened={passwordOpen} onClose={() => setPasswordOpen(false)} />
        <AuthModeModal opened={authModeOpen} onClose={() => setAuthModeOpen(false)} disable={!authDisabled} />
        <ResetModal opened={resetOpen} onClose={() => setResetOpen(false)} />
    </>
}
