import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import { SignupFormData, LoginFormData } from '@/lib/validations';

declare global {
  interface Window {
    _env_: {
      NEXT_PUBLIC_API_URL: string;
    };
  }
}

const API_URL = typeof window !== 'undefined' 
  ? (window._env_?.NEXT_PUBLIC_API_URL || 'http://localhost:8000')
  : 'http://localhost:8000';

interface AuthResponse {
  access: string;
  refresh: string;
  user: {
    id: number;
    email: string;
    username: string;
    profile_picture?: string;
  };
}

interface RefreshResponse {
  access: string;
}

// Get CSRF token from cookie
const getCsrfToken = (): string | null => {
  const name = 'csrftoken';
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop()?.split(';').shift() || null;
  return null;
};

// Create axios instance with default config
const api: AxiosInstance = axios.create({
  baseURL: API_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add CSRF token and auth token to requests
api.interceptors.request.use((config: AxiosRequestConfig) => {
  const token = localStorage.getItem('accessToken');
  const csrfToken = getCsrfToken();
  
  if (config.headers) {
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    if (csrfToken) {
      config.headers['X-CSRFToken'] = csrfToken;
    }
  }
  return config;
});

// Handle token refresh
api.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const refreshToken = localStorage.getItem('refreshToken');
        const response = await axios.post<RefreshResponse>(`${API_URL}/auth/token/refresh/`, {
          refresh: refreshToken,
        });
        const { access } = response.data;
        localStorage.setItem('accessToken', access);
        if (api.defaults.headers.common) {
          api.defaults.headers.common['Authorization'] = `Bearer ${access}`;
        }
        return api(originalRequest);
      } catch (refreshError) {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
        window.location.href = '/auth';
        return Promise.reject(refreshError);
      }
    }
    return Promise.reject(error);
  }
);

// Enhanced error handling
const handleAxiosError = (error: AxiosError): never => {
  if (error.response?.data?.message) {
    throw new Error(error.response.data.message);
  }
  if (error.response?.status === 401) {
    signOut(); // Force sign out on authentication error
    throw new Error('Session expired. Please sign in again.');
  }
  throw new Error(error.message || 'An unknown error occurred');
};

// Add token management
const setAuthTokens = (access: string, refresh: string) => {
  localStorage.setItem('accessToken', access);
  localStorage.setItem('refreshToken', refresh);
  if (api.defaults.headers.common) {
    api.defaults.headers.common['Authorization'] = `Bearer ${access}`;
  }
};

export const signupUser = async (data: SignupFormData): Promise<AuthResponse> => {
  try {
    const response = await api.post<AuthResponse>('/auth/register/', data);
    return response.data;
  } catch (err) {
    const error = err as AxiosError;
    if (error.response?.data?.message) {
      throw new Error(error.response.data.message);
    }
    throw new Error(error.message || 'An unknown error occurred');
  }
};

export const signinUser = async (data: LoginFormData): Promise<AuthResponse> => {
  try {
    const response = await api.post<AuthResponse>('/auth/token/', data);
    const { access, refresh } = response.data;
    setAuthTokens(access, refresh);
    return response.data;
  } catch (err) {
    return handleAxiosError(err as AxiosError);
  }
};

export const signOut = () => {
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  window.location.href = '/auth';
};

export const initiateGoogleLogin = () => {
  window.location.href = `${API_URL}/auth/google/login/`;
};

export const getProtectedData = async () => {
  try {
    const response = await api.get('/auth/protected/');
    return response.data;
  } catch (err) {
    const error = err as AxiosError;
    if (error.response?.data?.message) {
      throw new Error(error.response.data.message);
    }
    throw new Error(error.message || 'An unknown error occurred');
  }
};

export const isAuthenticated = () => {
  return !!localStorage.getItem('accessToken');
};