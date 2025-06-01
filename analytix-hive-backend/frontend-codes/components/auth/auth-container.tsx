"use client"

import * as React from "react"
import { LoginForm } from "./login-form"
import { SignupForm } from "./signup-form"
import type { LoginFormData, SignupFormData } from "@/lib/validations"

type AuthMode = "login" | "signup"

interface AuthContainerProps {
  initialMode?: AuthMode
  onLogin?: (data: LoginFormData) => Promise<void> | void
  onSignup?: (data: SignupFormData) => Promise<void> | void
  onForgotPassword?: () => void
  onGoogleSignIn?: () => Promise<void> | void
  isLoading?: boolean
}

export function AuthContainer({
  initialMode = "login",
  onLogin,
  onSignup,
  onForgotPassword,
  onGoogleSignIn,
  isLoading = false,
}: AuthContainerProps) {
  const [mode, setMode] = React.useState<AuthMode>(initialMode)

  const handleModeSwitch = (newMode: AuthMode) => {
    setMode(newMode)
  }

  if (mode === "signup") {
    return (
      <SignupForm
        onSubmit={onSignup}
        onLoginClick={() => handleModeSwitch("login")}
        onGoogleSignIn={onGoogleSignIn}
        isLoading={isLoading}
      />
    )
  }

  return (
    <LoginForm
      onSubmit={onLogin}
      onSignUpClick={() => handleModeSwitch("signup")}
      onForgotPasswordClick={onForgotPassword}
      onGoogleSignIn={onGoogleSignIn}
      isLoading={isLoading}
    />
  )
}
