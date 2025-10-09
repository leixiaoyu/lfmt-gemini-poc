import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL;

export const register = (userData: any) => {
  return axios.post(`${API_URL}/auth`, userData);
};

export const login = (credentials: any) => {
  return axios.post(`${API_URL}/auth/login`, credentials);
};

export const refreshToken = (token: any) => {
  return axios.post(`${API_URL}/auth/refresh`, { refreshToken: token });
};

export const resetPassword = (email: any) => {
  return axios.post(`${API_URL}/auth/reset-password`, { email });
};
