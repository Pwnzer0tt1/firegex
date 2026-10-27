import { Tooltip } from '@mantine/core'
import { NavLink, useLocation, useNavigate } from 'react-router'
import { PiWallLight } from 'react-icons/pi'
import { TbLayoutDashboard } from 'react-icons/tb'
import { useNavbarStore, useSystemStore } from '../../js/store'
import { firewallRulesQuery } from '../Firewall/utils'
import { Service } from '../Services/utils'
import InstanceMenu from './InstanceMenu'
import ProblemSummary from './ProblemSummary'
import { backendLink, Dot, serviceTone, toneColor, Tone } from './ui'

/** The port a service is best known by: its first address's. */
const primaryPort = (service: Service) => service.addresses?.[0]?.port

/**
 * The navigation, always on screen above 900px and a drawer below it.
 *
 * Besides the two pages it lists every service with a dot for its state, so that a
 * service going wrong is visible from whichever page is open and one click away.
 */
export default function Sidebar({ services }: { services: Service[] }) {
    const navigate = useNavigate()
    const location = useLocation()
    const { navOpened, closeNav, toggleNav } = useNavbarStore()
    const { version, socketConnected, socketEverConnected } = useSystemStore()
    const rules = firewallRulesQuery()

    const firewallOn = rules.data?.enabled ?? false
    const policy = rules.data?.policy ?? "accept"
    const firewallTone: Tone = firewallOn ? (policy === "accept" ? "ok" : "danger") : "muted"
    const running = services.filter(s => s.status === "active").length

    const sorted = [...services].sort((a, b) =>
        (primaryPort(a) ?? 0) - (primaryPort(b) ?? 0) || a.name.localeCompare(b.name))

    const backend = backendLink(socketConnected, socketEverConnected)

    return <>
        {navOpened && <div className="fg-nav-scrim" onClick={closeNav} />}
        <nav className={`fg-nav${navOpened ? " open" : ""}`} aria-label="Main">
            <a className="fg-nav-brand" href="/" onClick={e => { e.preventDefault(); navigate("/"); closeNav() }}>
                <img src="/header-logo.png" alt="" />
                <span>
                    <div className="fg-brand-name">Firegex</div>
                    <div className="fg-brand-sub">
                        {version && version !== "unknown" ? `v${version.replace(/^v/, "")} · ` : ""}by Pwnzer0tt1
                    </div>
                </span>
            </a>

            <div className="fg-nav-items">
                <NavLink to="/services" end onClick={closeNav}
                    className={({ isActive }) => `fg-nav-item${isActive ? " active" : ""}`}>
                    <TbLayoutDashboard size={17} />
                    <span>Services</span>
                    <span className="fg-nav-badge" style={{ color: "var(--fg-text-faint)" }}>
                        {services.length ? `${running}/${services.length}` : ""}
                    </span>
                </NavLink>
                <NavLink to="/firewall" onClick={closeNav}
                    className={({ isActive }) => `fg-nav-item${isActive ? " active" : ""}`}>
                    <PiWallLight size={17} />
                    <span>Firewall</span>
                    <span className="fg-nav-badge" style={{ color: toneColor[firewallTone] }}>
                        {rules.data ? (firewallOn ? policy : "off") : ""}
                    </span>
                </NavLink>
            </div>

            <div className="fg-nav-section">
                <span>Services</span>
                <span className="fg-mono">{services.length}</span>
            </div>
            <div className="fg-nav-services">
                {sorted.map(service => {
                    const path = `/services/${service.service_id}`
                    const active = location.pathname === path
                    const port = primaryPort(service)
                    return <NavLink key={service.service_id} to={path} onClick={closeNav}
                        className={`fg-nav-svc${active ? " active" : ""}`}
                        title={`${service.name}${port ? ` · ${port}/${service.proto}` : ""}`}>
                        <Dot tone={serviceTone(service)} />
                        <span className="fg-name">{service.name}</span>
                        <span className="fg-port">{port ?? "—"}</span>
                    </NavLink>
                })}
                {sorted.length === 0 && <span style={{ padding: "4px 10px", fontSize: 12, color: "var(--fg-text-faint)" }}>
                    none yet
                </span>}
            </div>

            <div className="fg-nav-foot">
                {/* Only the dot: the page header already says it in words, and the
                    tooltip says it here for whoever is on another page. */}
                <Tooltip label={`Backend ${backend.text}`} position="top-start">
                    <span role="status" aria-label={`Backend ${backend.text}`}
                        style={{ display: "inline-flex", alignItems: "center", padding: 6, cursor: "default" }}>
                        <Dot tone={backend.tone} pulse={!socketConnected && socketEverConnected} />
                    </span>
                </Tooltip>
                <span className="flex-spacer" />
                <ProblemSummary services={services} />
                <InstanceMenu />
            </div>
        </nav>
        {/* Hidden while the drawer is open: it would sit on the logo, and the scrim closes it. */}
        {!navOpened && <button type="button" className="fg-nav-toggle" onClick={toggleNav} aria-label="Menu">☰</button>}
    </>
}
