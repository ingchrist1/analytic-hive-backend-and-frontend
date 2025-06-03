import axios, { 
  AxiosInstance, 
  AxiosRequestConfig, 
  AxiosResponse, 
  AxiosError,
  InternalAxiosRequestConfig
} from 'axios';
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
  access_token: string;
  refresh_token: string;
  user: {
    id: number;
    email: string;
    username: string;
    profile_picture?: string;
    google_id?: string;
  };
}

interface RefreshResponse {
  access_token: string;
  refresh_token: string;
}

interface ApiError {
  message?: string;
  [key: string]: any;
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
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
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
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const refreshToken = localStorage.getItem('refreshToken');
        const response = await axios.post<RefreshResponse>(`${API_URL}/auth/token/refresh/`, {
          refresh_token: refreshToken,
        });
        const { access_token } = response.data;
        localStorage.setItem('accessToken', access_token);
        if (api.defaults.headers.common) {
          api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
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

// Enhanced error handling with better error messages
const handleAxiosError = (error: AxiosError<ApiError>): never => {
  if (error.response?.data) {
    const data = error.response.data;
    if (typeof data === 'object') {
      // Handle Django REST framework error format
      const messages = Object.values(data).flat();
      throw new Error(messages.join('. '));
    }
    throw new Error(String(data));
  }
  if (error.response?.status === 401) {
    signOut();
    throw new Error('Your session has expired. Please sign in again.');
  }
  if (error.response?.status === 403) {
    throw new Error('You do not have permission to perform this action.');
  }
  if (error.response?.status === 404) {
    throw new Error('The requested resource was not found.');
  }
  if (error.response?.status === 500) {
    throw new Error('An internal server error occurred. Please try again later.');
  }
  throw new Error(error.message || 'An unknown error occurred');
};

// Add token management
const setAuthTokens = (accessToken: string, refreshToken: string) => {
  localStorage.setItem('accessToken', accessToken);
  localStorage.setItem('refreshToken', refreshToken);
  if (api.defaults.headers.common) {
    api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
  }
};

export const signupUser = async (data: SignupFormData): Promise<AuthResponse> => {
  try {
    const response = await api.post<AuthResponse>('/auth/register/', data);
    const { access_token, refresh_token } = response.data;
    setAuthTokens(access_token, refresh_token);
    return response.data;
  } catch (err) {
 handleAxiosError(err as AxiosError<ApiError>);
  }
};

export const signinUser = async (data: LoginFormData): Promise<AuthResponse> => {
  try {
    const response = await api.post<AuthResponse>('/auth/login/', data);
    const { access_token, refresh_token } = response.data;
    setAuthTokens(access_token, refresh_token);
    return response.data;
  } catch (err) {
    handleAxiosError(err as AxiosError<ApiError>);
    throw new Error('Sign-in failed.'); // Ensure a return or throw
  }
};

export const getProtectedData = async (): Promise<any> => {
  try {
    const response = await api.get('/auth/protected/');
    return response.data;
  } catch (err) {
    handleAxiosError(err as AxiosError<ApiError>);
  }
};

export const isAuthenticated = (): boolean => {
  const token = localStorage.getItem('accessToken');
  return !!token;
};

