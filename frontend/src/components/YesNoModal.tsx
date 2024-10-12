import { Button, Group, Modal } from '@mantine/core';
import React from 'react';

function YesNoModal( { title, description, action, onClose, opened}:{ title:string, description:string, onClose:()=>void, action:()=>void, opened:boolean} ){

    return <Modal size="xl" title={title} opened={opened} onClose={onClose} centered>
            {description}
            <Group align="right" mt="md">
                <Button onClick={()=>{
                    onClose()
                    action()
                }} color="teal" type="submit">Yes</Button>
                <Button onClick={onClose} color="red" type="submit">No</Button>
                
            </Group>
          </Modal>
}

export default YesNoModal;