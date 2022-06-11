import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import MainLayout from './components/MainLayout';
import HomePage from './pages/HomePage';
import Service from './pages/Service';

function App() {
  return <MainLayout>
    <Routes>
      <Route index element={<HomePage />} />
      <Route path=":srv_id" element={<Service />} />
      <Route path="*" element={<Navigate to="/" />} />
    </Routes>
  </MainLayout>
}

export default App;
