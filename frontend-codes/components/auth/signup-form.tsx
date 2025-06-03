"use client"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PasswordInput } from "@/components/ui/password-input"
import { signupSchema, type SignupFormData } from "@/lib/validations"
import { cn } from "@/lib/utils"
import { useSignupMutation } from "@/hooks/useSignUp"
import { useRouter } from "next/navigation"
interface SignupFormProps {
  onSubmit?: (data: SignupFormData) => Promise<void> | void
  onLoginClick?: () => void
  onGoogleSignIn?: () => Promise<void> | void
  isLoading?: boolean
  className?: string
}

export function SignupForm({ onSubmit, onLoginClick, onGoogleSignIn, isLoading = false, className }: SignupFormProps) {
const signupMutation = useSignupMutation()
const router = useRouter()
 const {isSuccess}=signupMutation
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
    defaultValues: {
      name: "",
      email: "",
      password: "",
    },
  })

  const handleFormSubmit = async (data: SignupFormData) => {
    try {
      // await onSubmit?.(data)
      signupMutation.mutate(data)
      if (isSuccess) {
        router.push("/")
      }
    } catch (error) {
      console.error("Signup error:", error)
    }
  }

  const isFormLoading = isLoading || isSubmitting

  return (
    <div className={cn("w-full max-w-md mx-auto", className)}>
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm p-8">
        <div className="space-y-6">
          <div className="text-center">
            <h1 className="text-2xl font-semibold text-gray-900">Create an Account</h1>
          </div>

          <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email" className="text-sm font-medium text-gray-700">
                Name
              </Label>
              <Input
                id="name"
                type="name"
                placeholder="divine"
                className="h-12 border-gray-300 focus:border-orange-500 focus:ring-orange-500"
                {...register("name")}
                disabled={isFormLoading}
              />
              {errors.name && <p className="text-sm text-red-600">{errors.name.message}</p>}
            </div>
            <div className="space-y-2">
              <Label htmlFor="email" className="text-sm font-medium text-gray-700">
                Email
              </Label>
              <Input
                id="email"
                type="email"
                placeholder="divine@hive.com"
                className="h-12 border-gray-300 focus:border-orange-500 focus:ring-orange-500"
                {...register("email")}
                disabled={isFormLoading}
              />
              {errors.email && <p className="text-sm text-red-600">{errors.email.message}</p>}
            </div>

            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium text-gray-700">
                Password
              </Label>
              <PasswordInput
                id="password"
                placeholder="Enter your password"
                className="h-12 border-gray-300 focus:border-orange-500 focus:ring-orange-500"
                {...register("password")}
                disabled={isFormLoading}
              />
              {errors.password && (
                <div className="text-sm text-red-600">
                  <p className="font-medium">Password must:</p>
                  <ul className="list-disc list-inside space-y-1 mt-1">
                    {errors.password.message?.includes("8 characters") && <li>Be at least 8 characters long</li>}
                    {errors.password.message?.includes("letter") && <li>Contain at least one letter</li>}
                    {errors.password.message?.includes("number") && <li>Contain at least one number</li>}
                    {errors.password.message?.includes("special character") && (
                      <li>Contain at least one special character</li>
                    )}
                  </ul>
                </div>
              )}
            </div>

            <div className="space-y-3 pt-2">
              <Button
                type="submit"
                className="w-full h-12 bg-[#FDB606] hover:bg-[#fd9a06] text-white font-medium rounded-md transition-colors"
                disabled={isFormLoading}
              >
                {isFormLoading ? "Creating account..." : "Create account"}
              </Button>

              <Button
                type="button"
                variant="outline"
                className="w-full h-12 bg-blue-50 border-blue-200 text-blue-600 hover:bg-blue-100 font-medium rounded-md transition-colors"
                onClick={onGoogleSignIn}
                disabled={isFormLoading}
              >
                <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
                  <path
                    fill="currentColor"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="currentColor"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="currentColor"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                  />
                  <path
                    fill="currentColor"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                  />
                </svg>
                Continue with Google
              </Button>
            </div>
          </form>

          <div className="text-center">
            <span className="text-sm text-gray-600">
              {"Already Have An Account ? "}
              <button onClick={onLoginClick} className="text-gray-900 font-medium hover:underline transition-all">
                Log In
              </button>
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
