"use client"

import Image from "next/image"
import Link from "next/link"
import { Play, MoreVertical } from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

interface CourseProps {
  course: {
    id: string
    title: string
    image: string
    progress: number
  }
}

export function CourseCard({ course }: CourseProps) {
  return (
    <div className="bg-white rounded-lg overflow-hidden border border-gray-100">
      <Link href={`/courses/${course.id}`} className="block">
        <div className="relative h-40 w-full">
          <Image src={course.image || "/placeholder.svg"} alt={course.title} fill className="object-cover" />
          <div className="absolute top-2 right-2">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="bg-black/50 rounded-full p-1 text-white hover:bg-black/70 transition">
                  <MoreVertical className="h-5 w-5" />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem>Add to favorites</DropdownMenuItem>
                <DropdownMenuItem>Share course</DropdownMenuItem>
                <DropdownMenuItem>View details</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </Link>

      <div className="p-4">
        <Link href={`/courses/${course.id}`} className="block">
          <h3 className="font-medium text-lg mb-4">{course.title}</h3>
        </Link>

        <div className="flex items-center">
          <button
            className="bg-blue-600 text-white rounded-full p-2 mr-3 hover:bg-blue-700 transition"
            aria-label={`Play ${course.title}`}
          >
            <Play className="h-5 w-5 fill-current" />
          </button>

          <div className="flex-1">
            <div className="h-1 w-full bg-gray-200 rounded-full overflow-hidden">
              <div className="h-full bg-blue-600 rounded-full" style={{ width: `${course.progress}%` }} />
            </div>
            <span className="text-xs text-gray-500 mt-1 block">{course.progress}%</span>
          </div>
        </div>
      </div>
    </div>
  )
}
