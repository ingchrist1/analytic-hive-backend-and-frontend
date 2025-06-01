import { notFound } from "next/navigation"
import Image from "next/image"
import Link from "next/link"
import { ArrowLeft, Play } from "lucide-react"
import { CourseAccordion } from "../_components/course-accordion"
type PageProps = {
  params: Promise<{ courseId: string }>;
};
// Mock data for courses
const courses = [
  {
    id: "machine-learning",
    title: "Intro to Machine Learning",
    image: "/assets/ml.png",
    description: "Learn the fundamentals of machine learning algorithms and applications.",
    progress: 5,
    concepts: [
      "Introduction to ML Concepts",
      "Supervised Learning",
      "Unsupervised Learning",
      "Neural Networks Basics",
      "Decision Trees",
      "Support Vector Machines",
      "Evaluation Metrics",
      "Feature Engineering",
    ],
    resources: [
      { title: "ML Cheat Sheet", type: "PDF" },
      { title: "Python for ML", type: "Tutorial" },
      { title: "Dataset Repository", type: "Link" },
    ],
    relatedCourses: ["artificial-intelligence", "data-science", "deep-learning"],
  },
  {
    id: "virtual-reality",
    title: "Introduction to Virtual Reality",
    image: "/assets/virtual.png",
    description: "Explore the world of virtual reality and learn how to create immersive experiences.",
    progress: 0,
    concepts: [
      "VR Hardware Overview",
      "Spatial Computing",
      "User Interaction Design",
      "VR Development Tools",
      "3D Modeling for VR",
      "Performance Optimization",
    ],
    resources: [
      { title: "Unity VR Toolkit", type: "Software" },
      { title: "VR Design Principles", type: "Guide" },
      { title: "Oculus Developer Hub", type: "Link" },
    ],
    relatedCourses: ["augmented-reality", "game-development", "3d-modeling"],
  },
  {
    id: "artificial-intelligence",
    title: "Intro to Artificial Intelligence",
    image: "/assets/ai.png",
    description: "Understand the principles and applications of artificial intelligence.",
    progress: 0,
    concepts: [
      "AI Fundamentals",
      "Problem Solving by Search",
      "Knowledge Representation",
      "Machine Learning in AI",
      "Natural Language Processing",
      "Computer Vision",
      "Ethics in AI",
    ],
    resources: [
      { title: "AI Research Papers", type: "Collection" },
      { title: "TensorFlow Tutorials", type: "Tutorial" },
      { title: "AI Ethics Guidelines", type: "PDF" },
    ],
    relatedCourses: ["machine-learning", "deep-learning", "robotics"],
  },
]

export default async function CoursePage({ params }: PageProps) {
  const { courseId } = await params;
  const course = courses.find((c) => c.id === courseId)

  if (!course) {
    notFound()
  }

  // Mock data for related courses
  const relatedCoursesData = course.relatedCourses.map((id) => {
    const relatedCourse = courses.find((c) => c.id === id)
    return relatedCourse || { id, title: `Course: ${id}`, image: "/placeholder.svg?height=200&width=300" }
  })

  return (
    <div className="min-h-screen bg-gray-50 p-4 md:p-8">
      <div className="max-w-7xl mx-auto">
        <Link href="/courses" className="inline-flex items-center text-gray-600 mb-6 hover:text-gray-900">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Dashboard
        </Link>

        <div className="flex flex-col lg:flex-row gap-6">
          <div className="w-full lg:w-2/3">
            <div className="bg-white rounded-lg overflow-hidden shadow-sm">
              <div className="relative h-64 w-full">
                <Image src={course.image || "/placeholder.svg"} alt={course.title} fill className="object-cover" />
                <div className="absolute inset-0 bg-black/30 flex items-center justify-center">
                  <button
                    className="bg-blue-600 text-white rounded-full p-4 hover:bg-blue-700 transition transform hover:scale-105"
                    aria-label={`Play ${course.title}`}
                  >
                    <Play className="h-8 w-8 fill-current" />
                  </button>
                </div>
              </div>

              <div className="p-6">
                <h1 className="text-2xl font-bold mb-3">{course.title}</h1>
                <p className="text-gray-600 mb-4">{course.description}</p>

                <div className="mt-4">
                  <div className="flex items-center mb-2">
                    <span className="text-sm font-medium text-gray-500">Course Progress</span>
                    <span className="ml-auto text-sm font-medium">{course.progress}%</span>
                  </div>
                  <div className="h-2 w-full bg-gray-200 rounded-full overflow-hidden">
                    <div className="h-full bg-blue-600 rounded-full" style={{ width: `${course.progress}%` }} />
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-6 bg-white rounded-lg p-6 shadow-sm">
              <h2 className="text-xl font-bold mb-4">Course Content</h2>

              {/* Course content would go here */}
              <div className="space-y-4">
                <div className="p-4 border border-gray-200 rounded-lg">
                  <h3 className="font-medium">Module 1: Introduction</h3>
                  <p className="text-sm text-gray-600 mt-1">Learn the basics and get started with the course.</p>
                </div>
                <div className="p-4 border border-gray-200 rounded-lg">
                  <h3 className="font-medium">Module 2: Core Concepts</h3>
                  <p className="text-sm text-gray-600 mt-1">Dive deeper into the fundamental concepts.</p>
                </div>
                <div className="p-4 border border-gray-200 rounded-lg">
                  <h3 className="font-medium">Module 3: Advanced Topics</h3>
                  <p className="text-sm text-gray-600 mt-1">Explore advanced topics and real-world applications.</p>
                </div>
              </div>
            </div>
          </div>

          <div className="w-full lg:w-1/3 space-y-4">
            <CourseAccordion
              title="Concepts Viewed"
              icon="concepts"
              items={course.concepts.map((concept) => ({ title: concept }))}
              count={course.concepts.length}
            />

            <CourseAccordion
              title="Resources"
              icon="resources"
              items={course.resources}
              count={course.resources.length}
            />

            <CourseAccordion
              title="Related Courses"
              icon="courses"
              items={relatedCoursesData.map((c) => ({ title: c.title }))}
              count={relatedCoursesData.length}
              expanded={true}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
