import { ActionIcon, Badge, LoadingOverlay, NativeSelect, SegmentedControl, Space, Switch, Title, Tooltip } from "@mantine/core"
import { useEffect, useState } from "react";
import { BsPlusLg } from "react-icons/bs"
import { rem, Text } from '@mantine/core';
import { ActionType, Rule, firewall, firewallRulesQuery } from "../../components/Firewall/utils";
import cx from 'clsx'
import { errorNotify, getErrorMessage, okNotify } from "../../js/utils";
import { useListState } from '@mantine/hooks';
import { DragDropContext, Droppable, Draggable } from '@hello-pangea/dnd';
import { TbGripVertical, TbReload } from "react-icons/tb";
import classes from './DndListHandle.module.scss';
import { useQueryClient } from "@tanstack/react-query";
import { TiTick } from "react-icons/ti";
import YesNoModal from "../../components/YesNoModal";

  /*
  {
  "rules": [
    {
      "active": true,
      "name": "R1",
      "proto": "tcp",
      "ip_src": "0.0.0.0/0",
      "ip_dst": "0.0.0.0/0",
      "port_src_from": 1,
      "port_dst_from": 3030,
      "port_src_to": 65535,
      "port_dst_to": 3030,
      "action": "reject",
      "mode": "I"
    },
    {
      "active": true,
      "name": "R2",
      "proto": "tcp",
      "ip_src": "0.0.0.0/0",
      "ip_dst": "0.0.0.0/0",
      "port_src_from": 1,
      "port_dst_from": 3030,
      "port_src_to": 65535,
      "port_dst_to": 3030,
      "action": "drop",
      "mode": "O"
    },
    {
      "active": false,
      "name": "R3",
      "proto": "udp",
      "ip_src": "192.168.0.1/24",
      "ip_dst": "0.0.0.0/0",
      "port_src_from": 1,
      "port_dst_from": 2020,
      "port_src_to": 65535,
      "port_dst_to": 2020,
      "action": "drop",
      "mode": "I"
    },
    {
      "active": true,
      "name": "R4",
      "proto": "any",
      "ip_src": "::/0",
      "ip_dst": "fdfd::ffff:123/64",
      "port_src_from": 1,
      "port_dst_from": 1,
      "port_src_to": 1,
      "port_dst_to": 1,
      "action": "accept",
      "mode": "I"
    }
  ],
  "policy": "accept"
} 
  */

export const Firewall = () => {

    const [tooltipAddOpened, setTooltipAddOpened] = useState(false);
    const [tooltipRefreshOpened, setTooltipRefreshOpened] = useState(false);
    const [tooltipApplyOpened, setTooltipApplyOpened] = useState(false);
    const [open, setOpen] = useState(false);
    const [currentPolicy, setCurrentPolicy] = useState<ActionType>(ActionType.ACCEPT)
    const queryClient = useQueryClient()
    const rules = firewallRulesQuery()
    const [state, handlers] = useListState<Rule>([]);
    const [enableFwModal, setEnableFwModal] = useState(false)
    const [applyChangeModal, setApplyChangeModal] = useState(false)

    useEffect(()=> {
        if(rules.isError)
            errorNotify("Firewall Update failed!", getErrorMessage(rules.error))
    },[rules.isError])

    useEffect(()=> {
        if(!rules.isLoading && rules.isFetched && !rules.isFetching){
          setCurrentPolicy(rules.data?.policy??ActionType.ACCEPT)
          handlers.setState(JSON.parse(JSON.stringify(rules.data?.rules??[])))
        }
    },[rules.isFetched, rules.isLoading, rules.isFetching])

    const fwEnabled = rules.data?.enabled??false
    const valuesChanged = JSON.stringify(rules.data?.rules) != JSON.stringify(state) || rules.data?.policy != currentPolicy

    const enableFirewall = () => {
      if (valuesChanged){
        applyChangesRaw().then(()=>enableFirewallRaw())
      }else{
        enableFirewallRaw()
      }
    }

    const enableFirewallRaw = () => {
      return firewall.enable()
      .then(()=>okNotify("Firewall enabled", "The firewall has been enabled"))
      .catch((e)=>errorNotify("Firewall enable failed!", getErrorMessage(e)))
    }

    const disableFirewallRaw = () => {
      return firewall.disable()
      .then(()=>okNotify("Firewall disabled", "The firewall has been disabled"))
      .catch((e)=>errorNotify("Firewall disable failed!", getErrorMessage(e)))
    }

    const switchState = () => {
      if (fwEnabled)
        disableFirewallRaw()
      else
        if ([ActionType.REJECT, ActionType.DROP].includes(currentPolicy) || valuesChanged){
          setEnableFwModal(true)
        }else{
          enableFirewall()
        }
    }

    const applyChanges = () => {
      if (fwEnabled && rules.data?.policy == ActionType.ACCEPT && [ActionType.REJECT, ActionType.DROP].includes(currentPolicy)){
        setApplyChangeModal(true)
      }else{
        applyChangesRaw()
      }
    }

    const applyChangesRaw = () => {
      return firewall.ruleset({rules:state, policy:currentPolicy})
      .then(()=>okNotify("Firewall rules applied", "The firewall rules has been applied"))
      .catch((e)=>errorNotify("Firewall rules apply failed!", getErrorMessage(e)))
    }

    const items = state.map((item, index) => (
        <Draggable key={index} index={index} draggableId={index.toString()}>
          {(provided, snapshot) => (
            <div
              className={cx(classes.item, { [classes.itemDragging]: snapshot.isDragging })}
              ref={provided.innerRef}
              {...provided.draggableProps}
            >
              <div {...provided.dragHandleProps} className={classes.dragHandle}>
                <TbGripVertical style={{ width: rem(18), height: rem(18) }} />
              </div>
              <Space w="sm" />
              <Switch
                defaultChecked
                label="I agree to sell my privacy"
              />
              <div>
                <Text>{item.name}</Text>
                <Text c="dimmed" size="sm">
                  {JSON.stringify(item)}
                </Text>
              </div>
            </div>
          )}
        </Draggable>
      ));


    return <>
        <Space h="sm" />
        <LoadingOverlay visible={rules.isLoading} />
        <div className='center-flex'>
            <Title order={3}>Firewall Rules</Title>
            <div className='flex-spacer' />
            Enabled: <Space w="sm" /> <Switch checked={fwEnabled} onChange={switchState} />
            <Space w="sm" />
            Policy:
            <Space w="xs" />
            <SegmentedControl
                data={[
                    {
                      value: ActionType.ACCEPT,
                      label: 'Accept',
                    },
                    {
                      value: ActionType.REJECT,
                      label: 'Reject',
                    },
                    {
                      value: ActionType.DROP,
                      label: 'Drop',
                    }
                ]}
                value={currentPolicy}
                onChange={(value)=>setCurrentPolicy(value as ActionType)}
            />
            <Space w="xs" />
            <Badge size="sm" color="green" variant="filled">Rules: {rules.isLoading?0:rules.data?.rules.length}</Badge>
            <Space w="xs" />
            <Tooltip label="Add a new rule" position='bottom' color="blue" opened={tooltipAddOpened}>
                <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"
                onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
                onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size={18} /></ActionIcon>
            </Tooltip>
            <Space w="xs" />
            <Tooltip label="Refresh" position='bottom' color="indigo" opened={tooltipRefreshOpened}>
                <ActionIcon color="indigo" onClick={()=>queryClient.invalidateQueries(["firewall"])} size="lg" radius="md" variant="filled"
                loading={rules.isFetching}
                onFocus={() => setTooltipRefreshOpened(false)} onBlur={() => setTooltipRefreshOpened(false)}
                onMouseEnter={() => setTooltipRefreshOpened(true)} onMouseLeave={() => setTooltipRefreshOpened(false)}><TbReload size={18} /></ActionIcon>
            </Tooltip>
            <Space w="xs" />
            <Tooltip label="Apply" position='bottom' color="grape" opened={tooltipApplyOpened}>
                <ActionIcon color="grape" onClick={applyChanges} size="lg" radius="md" variant="filled"
                onFocus={() => setTooltipApplyOpened(false)} onBlur={() => setTooltipApplyOpened(false)}
                onMouseEnter={() => setTooltipApplyOpened(true)} onMouseLeave={() => setTooltipApplyOpened(false)}
                disabled={!valuesChanged}
                ><TiTick size={22} /></ActionIcon>
            </Tooltip>
        </div>
        <Space h="xl" />
        
        <DragDropContext
      onDragEnd={({ destination, source }) =>
        handlers.reorder({ from: source.index, to: destination?.index || 0 })
      }
    >
      <Droppable droppableId="dnd-list" direction="vertical">
        {(provided) => (
          <div {...provided.droppableProps} ref={provided.innerRef}>
            {items}
            {provided.placeholder}
          </div>
        )}
      </Droppable>
    </DragDropContext>

      <YesNoModal
          title='Are you sure to apply the changes to the firewall?'
          description={`If there is a malconfiguration you can lose the access to your server! ⚠️`}
          onClose={()=>setEnableFwModal(false) }
          action={enableFirewall}
          opened={enableFwModal}
      />

      <YesNoModal
          title='Are you sure to apply the changes to the firewall?'
          description={`If there is a malconfiguration you can lose the access to your server! ⚠️`}
          onClose={()=>setApplyChangeModal(false) }
          action={applyChangesRaw}
          opened={applyChangeModal}
      />

    </>
}