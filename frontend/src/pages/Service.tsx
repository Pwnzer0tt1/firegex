import React from 'react';
import { useParams } from 'react-router-dom';

function Service() {
    const {srv_id} = useParams()
    return <div>
        Service: {srv_id}
    </div>
}

export default Service;
