"use client"
import { AuthContainer } from "@/components/auth/auth-container"
import type { LoginFormData, SignupFormData } from "@/lib/validations"

export default function AuthPage() {
  const handleLogin = async (data: LoginFormData) => {
    console.log("Login data:", data)
    // Implement your login logic here
    // Example: await signIn(data.email, data.password)
  }

  const handleSignup = async (data: SignupFormData) => {
    console.log("Signup data:", data)
    // Implement your signup logic here
    // Example: await createUser(data.email, data.password)
  }

  const handleForgotPassword = () => {
    console.log("Forgot password clicked")
    // Implement forgot password logic
    // Example: redirect to forgot password page
  }

  const handleGoogleSignIn = async () => {
    console.log("Google sign in clicked")
    // Implement Google OAuth logic
    // Example: await signInWithGoogle()
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <AuthContainer
        initialMode="login"
        onLogin={handleLogin}
        onSignup={handleSignup}
        onForgotPassword={handleForgotPassword}
        onGoogleSignIn={handleGoogleSignIn}
      />
    </div>
  )
}
