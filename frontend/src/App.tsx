import React from 'react';
import { Navigate, Outlet, Route, Routes } from 'react-router-dom';
import MainLayout from './components/MainLayout';
import HomePage from './pages/HomePage';
import ServiceDetails from './pages/ServiceDetails';

function App() {
  return <Routes>
        <Route element={<MainLayout><Outlet /></MainLayout>}>
          <Route index element={<HomePage />} />
          <Route path=":srv_id" element={<ServiceDetails />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Route>
    </Routes>
}

export default App;
