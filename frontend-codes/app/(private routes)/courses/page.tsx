import Link from "next/link"
import { CourseCard } from "./_components/course-card"

import { StatCard } from "./_components/stat-card"
import { HelpCard } from "./_components/help-card"
import { ArrowRight } from "lucide-react"

// Mock data for courses
const courses = [
  {
    id: "machine-learning",
    title: "Intro to Machine Learning",
    image: "/assets/ml.png",
    progress: 5,
  },
  {
    id: "virtual-reality",
    title: "Introduction to Virtual Reality",
    image: "/assets/ai.png",
    progress: 0,
  },
  {
    id: "artificial-intelligence",
    title: "Intro to Artificial Intelligence",
    image: "/assets/virtual.png",
    progress: 0,
  },
]

export default function Home() {
  return (
    <div className="min-h-screen bg-gray-50 p-4 md:p-8">
      <div className="max-w-[1440px] mx-auto">
        <h1 className="text-3xl font-bold mb-6">Welcome Divine</h1>

        <div className="flex flex-col lg:flex-row gap-6">
          <div className="w-full lg:w-2/3 bg-white rounded-lg p-6 shadow-sm">
            <h2 className="text-xl font-bold mb-4">Continue Learning</h2>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {courses.map((course) => (
                <CourseCard key={course.id} course={course} />
              ))}
            </div>

            <div className="mt-6 flex justify-start">
              <Link href="/courses" className="text-blue-600 font-medium flex items-center hover:underline">
                View All <ArrowRight className="ml-1 h-4 w-4" />
              </Link>
            </div>
          </div>

          <div className="w-full lg:w-1/3 space-y-4">
            <StatCard icon="concepts" title="Concepts Viewed" count={51} />
            <StatCard icon="lessons" title="Lessons Viewed" count={2} />
            <StatCard icon="quizzes" title="Quizzes Completed" count={9} />
            <StatCard icon="projects" title="Projects Passed" count={0} />
            <StatCard icon="programs" title="Programs Completed" count={0} />

            <HelpCard icon="lesson" title="Lesson Help" linkText="Visit Knowledge Q&A" href="/knowledge" />
            <HelpCard icon="account" title="Account Help" linkText="Visit Help Center" href="/help" />
            <HelpCard icon="community" title="Community" linkText="Visit Community" href="/community" />
          </div>
        </div>
      </div>
    </div>
  )
}
