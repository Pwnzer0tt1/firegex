# **WORK IN PROGRESS**

# Firegex-API Documentation
### This is a short description of the API

#
# Documentation
## Index

- [General stats](#get-apigeneral-stats)
- [List services](#get-apiservices)
- [Service info](#get-apiserviceserv)
- [Stop service](#get-apiserviceservstop)
- [Start service](#get-apiserviceservstart)
- [Delete service](#get-apiserviceservdelete)
- [Terminate service](#get-apiserviceservterminate)
- [Regenerate public port](#get-apiserviceservregen-port)
- [Service regexes](#get-apiserviceservregexes)
- [Regex info](#get-apiregexregexid)
- [Delete regex](#get-apiregexregexiddelete)
- [Add regex](#post-apiregexesadd)
- [Add service](#post-apiservicesadd)

#
#
## **GET** **```/api/general-stats```**
### Server response:
```json
{
    "services": <total number of services>,
    "closed": <total number of rejected packets>,
    "regex": <total number of regexes>
}
```

#
## **GET** **```/api/services```**
### Server response:
```json
[
    {
        "id": <service_id>,
        "status": <service status>,
        "public_port": <public port>,
        "internal_port": <internal port>,
        "n_pacchetti": <number of rejected packets>,
        "n_regex": <number of regexes>
    },
    {
        // Another service
    }
]
```

#
## **GET** **```/api/service/<serv>```**
### Server response:
```json
{
    "id": <service_id>,
    "status": <service status>,
    "public_port": <public port>,
    "internal_port": <internal port>,
    "n_pacchetti": <number of rejected packets>,
    "n_regex": <number of regexes>
}
```

#
## **GET** **```/api/service/<serv>/stop```**
### Server response:
```json
{
    "status": "ok"
}
```

#
## **GET** **```/api/service/<serv>/start```**
### Server response:
```json
{
    "status": "ok"
}
```

#
## **GET** **```/api/service/<serv>/delete```**
### Server response:
```json
{
    "status": "ok"
}
```

#
## **GET** **```/api/service/<serv>/terminate```**
### Server response:
```json
{
    "status": "ok"
}
```

#
## **GET** **```/api/service/<serv>/regen-port```**
### Server response:
```json
{
    "status": "ok"
}
```

#
## **GET** **```/api/service/<serv>/regexes```**
### Server response:
```json
[
    {
        "id": <regex id>,
        "service_id": <service_id>,
        "regex": <base64 encoded regex>,
        "is_blacklist": <true|false>,
        "mode": <"C"|"S"|"B"> // Client to server, server to client or both
    },
    {
        // Another regex
    }
]
```

#
## **GET** **```/api/regex/<regex_id>```**
### Server response:
```json
{
    "id": <regex id>,
    "service_id": <service_id>,
    "regex": <base64 encoded regex>,
    "is_blacklist": <true|false>,
    "mode" <"C"|"S"|"B"> // Client to server, server to client or both
}
```

#
## **GET** **```/api/regex/<regex_id>/delete```**
### Server response:
```json
{
    "status": "ok"
}
```

#
## **POST** **```/api/regexes/add```**
### Client request:
```json
{
    "service_id": <service_id>,
    "regex": <base64 encoded regex>,
    "is_blacklist": <true|false>,
    "mode": <"C"|"S"|"B"> // Client to server, server to client or both
}
```
### Server response:
```json
{
    "status": "ok"
}
```

#
## **POST** **```/api/services/add```**
### Client request:
```json
{
    "name": <the id used to identify the service>,
    "port": <the internal port>
}
```
### Server response:
```json
{
    "status": "ok"
}
```