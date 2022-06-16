import { ActionIcon, Grid, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import React, { useEffect, useState } from 'react';
import { BsTrashFill } from 'react-icons/bs';
import { useNavigate, useParams } from 'react-router-dom';
import RegexView from '../components/RegexView';
import ServiceRow from '../components/ServiceRow';
import AddNewRegex from '../components/AddNewRegex';
import { BsPlusLg } from "react-icons/bs";
import YesNoModal from '../components/YesNoModal';
import { RegexFilter, Service } from '../js/models';
import { deleteservice, errorNotify, eventUpdateName, fireUpdateRequest, okNotify, regenport, serviceinfo, serviceregexlist } from '../js/utils';
import { BsArrowRepeat } from "react-icons/bs"
import { useWindowEvent } from '@mantine/hooks';

function ServiceDetails() {
    const {srv_id} = useParams()

    const [serviceInfo, setServiceInfo] = useState<Service>({
        id:srv_id?srv_id:"",
        internal_port:0,
        n_packets:0,
        n_regex:0,
        name:srv_id?srv_id:"",
        public_port:0,
        status:"🤔"
    })

    const [regexesList, setRegexesList] = useState<RegexFilter[]>([])
    const [loader, setLoader] = useState(true);
    const [open, setOpen] = useState(false);
    const closeModal = () => {setOpen(false);updateInfo();}

    const updateInfo = async () => {
        if (!srv_id) return
        let error = false;
        await serviceinfo(srv_id).then(res => {
            setServiceInfo(res)
        }).catch(
          err =>{
            error = true;
            navigator("/")
        })
        if (error) return
        await serviceregexlist(srv_id).then(res => {
            setRegexesList(res)
        }).catch(
          err => errorNotify(`Updater for ${srv_id} service failed [Regex list]!`, err.toString())
        )
        setLoader(false)
    }

    useWindowEvent(eventUpdateName, updateInfo)
    useEffect(fireUpdateRequest,[])

    const navigator = useNavigate()

    const [deleteModal, setDeleteModal] = useState(false)
    const [changePortModal, setChangePortModal] = useState(false)
    const [tooltipDeleteOpened, setTooltipDeleteOpened] = useState(false);
    const [tooltipChangeOpened, setTooltipChangeOpened] = useState(false);
    const [tooltipAddRegexOpened, setTooltipAddRegexOpened] = useState(false);
    
    const deleteService = () => {
        deleteservice(serviceInfo.id).then(res => {
            if (!res){
                okNotify("Service delete complete!",`The service ${serviceInfo.id} has been deleted!`)
                updateInfo();
            }else
                errorNotify("An error occurred while deleting a service",`Error: ${res}`)
        }).catch(err => {
            errorNotify("An error occurred while deleting a service",`Error: ${err}`)
        })
        
    }

    const changePort = () => {
        regenport(serviceInfo.id).then(res => {
            if (!res){
                okNotify("Service port regeneration completed!",`The service ${serviceInfo.id} has changed the internal port!`)
                updateInfo();
            }else
                errorNotify("An error occurred while changing the internal service port",`Error: ${res}`)
        }).catch(err => {
            errorNotify("An error occurred while changing the internal service port",`Error: ${err}`)
        })
    }

    return <div>
        <LoadingOverlay visible={loader} />
        <ServiceRow service={serviceInfo} additional_buttons={<>
            <Tooltip label="Delete service" zIndex={0} transition="pop" transitionDuration={200} /*openDelay={500}*/ transitionTimingFunction="ease" color="red" opened={tooltipDeleteOpened} tooltipId="tooltip-delete-id">           
                <ActionIcon color="red" onClick={()=>setDeleteModal(true)} size="xl" radius="md" variant="filled"
                 aria-describedby="tooltip-delete-id"
                 onFocus={() => setTooltipDeleteOpened(false)} onBlur={() => setTooltipDeleteOpened(false)}
                 onMouseEnter={() => setTooltipDeleteOpened(true)} onMouseLeave={() => setTooltipDeleteOpened(false)}
                 ><BsTrashFill size={22} /></ActionIcon>
            </Tooltip>
            <Space w="md"/>
            <Tooltip label="Change proxy port" zIndex={0} transition="pop" transitionDuration={200} /*openDelay={500}*/ transitionTimingFunction="ease" color="blue" opened={tooltipChangeOpened} tooltipId="tooltip-change-id">           
                <ActionIcon color="blue" onClick={()=>setChangePortModal(true)} size="xl" radius="md" variant="filled"
                aria-describedby="tooltip-change-id"
                onFocus={() => setTooltipChangeOpened(false)} onBlur={() => setTooltipChangeOpened(false)}
                onMouseEnter={() => setTooltipChangeOpened(true)} onMouseLeave={() => setTooltipChangeOpened(false)}
                ><BsArrowRepeat size={28} /></ActionIcon>
            </Tooltip>
            <Space w="md"/>
        </>}></ServiceRow>
        
        {regexesList.length === 0?<>
                <Space h="xl" />
                <Title className='center-flex' align='center' order={3}>No regex found for this service! Add one by clicking the "+" buttons</Title>
                <Space h="xl" /> <Space h="xl" /> <Space h="xl" /> <Space h="xl" />
                <div className='center-flex'>
                    <Tooltip label="Add a new regex" zIndex={0} transition="pop" transitionDuration={200} /*openDelay={500}*/ transitionTimingFunction="ease" color="blue" opened={tooltipAddRegexOpened} tooltipId="tooltip-AddRegex-id">
                        <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"
                         aria-describedby="tooltip-AddRegex-id"
                         onFocus={() => setTooltipAddRegexOpened(false)} onBlur={() => setTooltipAddRegexOpened(false)}
                         onMouseEnter={() => setTooltipAddRegexOpened(true)} onMouseLeave={() => setTooltipAddRegexOpened(false)}><BsPlusLg size="20px" /></ActionIcon>
                    </Tooltip>
                </div>
            </>:
            <Grid>
                {regexesList.map( (regexInfo) => <Grid.Col key={regexInfo.id} lg={6} xs={12}><RegexView regexInfo={regexInfo} /></Grid.Col>)}
            </Grid>
        }

        {srv_id?<AddNewRegex opened={open} onClose={closeModal} service={srv_id} />:null}

        <YesNoModal
            title='Are you sure to delete this service?'
            description={`You are going to delete the service '${serviceInfo.id}', causing the stopping of the firewall and deleting all the regex associated. This will cause the shutdown of your service! ⚠️`}
            onClose={()=>setDeleteModal(false) }
            action={deleteService}
            opened={deleteModal}
        />
        <YesNoModal
            title='Are you sure to change the proxy internal port?'
            description={`You are going to change the proxy port '${serviceInfo.internal_port}'. This will cause the shutdown of your service temporarily! ⚠️`}
            onClose={()=>setChangePortModal(false)}
            action={changePort}
            opened={changePortModal}
        />
    </div>
}

export default ServiceDetails;
