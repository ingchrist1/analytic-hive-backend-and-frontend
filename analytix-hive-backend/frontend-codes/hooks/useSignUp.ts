
"use client"
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { SignupFormData } from '@/lib/validations';
import { signupUser } from '@/services/auth';
import { toast } from 'sonner';
import { useRouter } from 'next/navigation';
// Types for the signup request and response


type SignupResponse = any



// Custom hook for signup mutation
export const useSignupMutation = () => {

  return useMutation<SignupResponse, Error, SignupFormData>({
    mutationFn: signupUser,
    
    onSuccess: (data) => {
   
      console.log('Signup successful:', data);

      toast.success('Welcome!', {
        description: `Account created successfully for`,
      });
    },
    
    onError: (error) => {
    console.error('Signup failed:', error.message);
    toast.error('Signup Failed', {
        description: error.message || 'Something went wrong. Please try again.',
        duration: 5000,
      });
    },
    
  
  } );
};