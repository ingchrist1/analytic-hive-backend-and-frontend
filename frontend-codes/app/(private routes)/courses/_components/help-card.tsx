import Link from "next/link"
import { MessageSquare, HelpCircle, Users, ArrowRight } from "lucide-react"

interface HelpCardProps {
  icon: "lesson" | "account" | "community"
  title: string
  linkText: string
  href: string
}

export function HelpCard({ icon, title, linkText, href }: HelpCardProps) {
  const getIcon = () => {
    switch (icon) {
      case "lesson":
        return <MessageSquare className="h-6 w-6" />
      case "account":
        return <HelpCircle className="h-6 w-6" />
      case "community":
        return <Users className="h-6 w-6" />
      default:
        return null
    }
  }

  return (
    <div className="bg-white rounded-lg p-4 border border-gray-100 shadow-sm">
      <div className="flex items-center mb-2">
        {getIcon()}
        <span className="ml-2 font-medium">{title}</span>
      </div>
      <Link href={href} className="text-blue-600 font-medium flex items-center hover:underline">
        {linkText} <ArrowRight className="ml-1 h-4 w-4" />
      </Link>
    </div>
  )
}
