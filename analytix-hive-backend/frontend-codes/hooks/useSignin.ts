
"use client"
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { LoginFormData } from '@/lib/validations';
import { signinUser } from '@/services/auth';
import { toast } from 'sonner';



type SignupResponse = any



// Custom hook for login mutation
export const useSigninMutation = () => {
  return useMutation<SignupResponse, Error, LoginFormData>({
    mutationFn: signinUser,
    onSuccess: (data) => {
      console.log('Login successful:', data);
      toast.success('Welcome back!', {
        description: 'You have successfully logged in.',
      });
    },
    onError: (error) => {
      console.error('Login failed:', error.message);
      toast.error('Login Failed', {
        description: error.message || 'Invalid email or password. Please try again.',
        duration: 5000,
      });
    },
  });
};