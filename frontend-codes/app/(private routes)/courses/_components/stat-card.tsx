import { FileText, BookOpen, CheckSquare, Award, Medal } from "lucide-react"

interface StatCardProps {
  icon: "concepts" | "lessons" | "quizzes" | "projects" | "programs"
  title: string
  count: number
}

export function StatCard({ icon, title, count }: StatCardProps) {
  const getIcon = () => {
    switch (icon) {
      case "concepts":
        return <FileText className="h-6 w-6 text-blue-500" />
      case "lessons":
        return <BookOpen className="h-6 w-6 text-teal-500" />
      case "quizzes":
        return <CheckSquare className="h-6 w-6 text-teal-500" />
      case "projects":
        return <Award className="h-6 w-6 text-teal-500" />
      case "programs":
        return <Medal className="h-6 w-6 text-blue-500" />
      default:
        return null
    }
  }

  return (
    <div className="bg-white rounded-lg p-4 border border-gray-100 shadow-sm flex items-center justify-between">
      <div className="flex items-center">
        {getIcon()}
        <span className="ml-3 font-medium">{title}</span>
      </div>
      <span className="font-bold text-lg">{count}</span>
    </div>
  )
}
