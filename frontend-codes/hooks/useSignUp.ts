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

      // Show success toast with more prominence
      toast.success('Account Created Successfully!', {
        description: 'Your account has been created. Please sign in with your credentials.',
        duration: 5000,
        style: { fontWeight: 'bold' }, // Replace 'important' with a valid style property
        action: {
          label: 'Sign In',
          onClick: () => window.location.reload()
        },
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