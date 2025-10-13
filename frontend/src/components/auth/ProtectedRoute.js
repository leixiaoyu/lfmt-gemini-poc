import React from 'react';
import { Navigate } from 'react-router-dom';

const ProtectedRoute = ({ children }) => {
  // Assumption: Auth token is stored in localStorage after login.
  // In a real app, this would be managed by a global auth context.
  const authToken = localStorage.getItem('authToken');

  if (!authToken) {
    // If no token, redirect to the login page
    return <Navigate to="/login" replace />;
  }

  return children;
};

export default ProtectedRoute;
