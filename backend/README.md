# Firegex backend

## [GO BACK](../README.md)

The backend of firegex is written with fastapi. The aim of the backend is to manage all the requests from the react front-end and manage also the proxy processes of the entire firewall. The fastapi webserver is responsable of deploying the react app.

```mermaid
flowchart LR
    admin(["👤 Team members"])
    clients(["🌐 Other teams<br/>& checkers"])

    subgraph control["Control plane"]
        direction TB
        ui["Web UI<br/><i>React · Vite · Mantine</i>"]
        api["Backend<br/><i>FastAPI · Socket.IO</i>"]
        db[("SQLite")]
        ui <-->|"REST · live updates"| api
        api --- db
    end

    subgraph host["Linux host · kernel"]
        direction TB
        nft{{"nftables<br/><i>table inet fgex</i>"}}

        subgraph datapath["Data plane · one engine per service"]
            direction TB
            nfq["<b>NFQUEUE layer</b><br/>cppregex · cpproxy (C++)<br/><i>per-packet verdict, kernel fail-open</i>"]
            proxy["<b>Proxy layer</b><br/>fgex-proxy (Rust)<br/><i>TCP · UDP · TLS · QUIC<br/>HTTP/1.1 · HTTP/2 · HTTP/3</i>"]
            ext["<b>External layer</b><br/><i>hand-off to your own proxy</i>"]
        end

        subgraph chain["Filter chain"]
            direction TB
            rx["Regex<br/><i>Hyperscan</i>"]
            py["Python filters<br/><i>firegex.pyfilters</i>"]
        end

        fw["Firewall rules<br/><i>fgex_filter</i>"]
        cap["firegex0<br/><i>decrypted capture</i>"]
    end

    svc[["🖥️ Protected services"]]

    admin --> ui
    api -->|"rules"| nft
    api -->|"spawn · configure · stats"| datapath
    api -->|"rules"| fw

    clients ==> nft
    nft ==>|"queue / redirect"| nfq & proxy
    nft ==>|"rewrite"| ext
    nfq & proxy -.->|"judge"| chain
    proxy -.-> cap
    nfq & proxy & ext ==>|"filtered traffic"| svc

    classDef ctl fill:#dbeafe,stroke:#2563eb,color:#0f172a
    classDef dp fill:#fee2e2,stroke:#dc2626,color:#0f172a
    classDef flt fill:#dcfce7,stroke:#16a34a,color:#0f172a
    classDef ext fill:#f1f5f9,stroke:#64748b,color:#0f172a
    class ui,api,db ctl
    class nfq,proxy,ext,nft,fw dp
    class rx,py flt
    class admin,clients,svc,cap ext
```
Schematic example about how firegex manage the filters

### Read the documentation of the API going at `/api/docs` path and see the swagger documentation of the API.

## [GO BACK](../README.md)
