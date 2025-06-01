import { SignupFormData, LoginFormData } from '@/lib/validations';
import { api } from '@/config/api';

export const signupUser = async (data: SignupFormData) => {
  try {
    const response = await api.post('/auth/register/', data);
    if (response.data.token) {
      localStorage.setItem('auth_token', response.data.token);
    }
    return response.data;
  } catch (err: any) {
    if (err.response && err.response.data?.message) {
      throw new Error(err.response.data.message);
    }
    throw new Error(err.message || 'An unknown error occurred');
  }
};

export const signinUser = async (data: LoginFormData) => {
  try {
    const response = await api.post('/auth/token/', {
      email: data.email,
      password: data.password
    });
    if (response.data.access) {
      localStorage.setItem('auth_token', response.data.access);
      localStorage.setItem('refresh_token', response.data.refresh);
    }
    return response.data;
  } catch (err: any) {
    if (err.response && err.response.data?.detail) {
      throw new Error(err.response.data.detail);
    }
    throw new Error(err.message || 'An unknown error occurred');
  }
};

export const signOutUser = async () => {
  try {
    await api.post('/auth/logout/');
    localStorage.removeItem('auth_token');
  } catch (err: any) {
    console.error('Error during logout:', err);
  }
};

export const getCurrentUser = async () => {
  try {
    const response = await api.get('/auth/user/');
    return response.data;
  } catch (err: any) {
    if (err.response?.status === 401) {
      localStorage.removeItem('auth_token');
    }
    throw err;
  }
};