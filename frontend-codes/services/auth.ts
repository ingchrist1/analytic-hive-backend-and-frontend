import axios from 'axios';
import { SignupFormData, LoginFormData } from '@/lib/validations';

declare global {
  interface Window {
    _env_: {
      NEXT_PUBLIC_API_URL: string;
    };
  }
}

const API_URL = typeof window !== 'undefined' 
  ? (window._env_?.NEXT_PUBLIC_API_URL || 'http://localhost:8002')
  : 'http://localhost:8002';

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
const api = axios.create({
  baseURL: API_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add CSRF token and auth token to requests
api.interceptors.request.use((config) => {
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
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) {
          throw new Error('No refresh token available');
        }
        
        const response = await axios.post<RefreshResponse>(`${API_URL}/auth/token/refresh/`, {
          refresh: refreshToken,
        });
        
        const { access_token, refresh_token } = response.data;
        setAuthTokens(access_token, refresh_token);
        
        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${access_token}`;
        }
        return api(originalRequest);
      } catch (refreshError) {
        signOut();
        return Promise.reject(refreshError);
      }
    }
    return Promise.reject(error);
  }
);

interface AxiosErrorResponse {
  response?: {
    data?: any;
    status?: number;
  };
  message?: string;
}

// Enhanced error handling with better error messages
const handleAxiosError = (error: unknown): never => {
  const axiosError = error as AxiosErrorResponse;
  
  if (axiosError.response?.data) {
    const data = axiosError.response.data;
    if (typeof data === 'object') {
      const messages = Object.values(data).flat();
      throw new Error(messages.join('. '));
    }
    throw new Error(String(data));
  }
  
  if (axiosError.response?.status === 401) {
    signOut();
    throw new Error('Your session has expired. Please sign in again.');
  }
  if (axiosError.response?.status === 403) {
    throw new Error('You do not have permission to perform this action.');
  }
  if (axiosError.response?.status === 404) {
    throw new Error('The requested resource was not found.');
  }
  if (axiosError.response?.status === 500) {
    throw new Error('An internal server error occurred. Please try again later.');
  }
  
  throw new Error(axiosError.message || 'An unknown error occurred');
};

// Add token management
const setAuthTokens = (accessToken: string, refreshToken: string) => {
  localStorage.setItem('accessToken', accessToken);
  localStorage.setItem('refreshToken', refreshToken);
  if (api.defaults.headers.common) {
    api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
  }
};

// Sign out user and clear tokens
const signOut = () => {
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  if (api.defaults.headers.common) {
    delete api.defaults.headers.common['Authorization'];
  }
  window.location.href = '/auth';
};

export const signupUser = async (data: SignupFormData): Promise<AuthResponse> => {
  try {
    const response = await api.post<AuthResponse>('/auth/register/', data);
    const { access_token, refresh_token } = response.data;
    setAuthTokens(access_token, refresh_token);
    return response.data;
  } catch (err) {
    throw handleAxiosError(err);
  }
};

export const signinUser = async (data: LoginFormData): Promise<AuthResponse> => {
  try {
    const response = await api.post<AuthResponse>('/auth/token/', data);
    const { access_token, refresh_token } = response.data;
    setAuthTokens(access_token, refresh_token);
    return response.data;
  } catch (err) {
    throw handleAxiosError(err);
  }
};

export const getProtectedData = async (): Promise<any> => {
  try {
    const response = await api.get('/auth/protected/');
    return response.data;
  } catch (err) {
    throw handleAxiosError(err);
  }
};

export const isAuthenticated = (): boolean => {
  const token = localStorage.getItem('accessToken');
  return !!token;
};

