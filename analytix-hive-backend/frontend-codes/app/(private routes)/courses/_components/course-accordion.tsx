"use client"

import { useState } from "react"
import { ChevronDown, FileText, BookOpen, Layers } from "lucide-react"
import { cn } from "@/lib/utils"

interface AccordionItem {
  title: string
  type?: string
}

interface CourseAccordionProps {
  title: string
  icon: "concepts" | "resources" | "courses"
  items: AccordionItem[]
  count: number
  expanded?: boolean
}

export function CourseAccordion({ title, icon, items, count, expanded = false }: CourseAccordionProps) {
  const [isOpen, setIsOpen] = useState(expanded)

  const getIcon = () => {
    switch (icon) {
      case "concepts":
        return <FileText className="h-6 w-6 text-blue-500" />
      case "resources":
        return <BookOpen className="h-6 w-6 text-teal-500" />
      case "courses":
        return <Layers className="h-6 w-6 text-purple-500" />
      default:
        return null
    }
  }

  return (
    <div className="bg-white rounded-lg border border-gray-100 shadow-sm overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full p-4 flex items-center justify-between focus:outline-none"
        aria-expanded={isOpen}
      >
        <div className="flex items-center">
          {getIcon()}
          <span className="ml-3 font-medium">{title}</span>
        </div>
        <div className="flex items-center">
          <span className="mr-2 font-bold">{count}</span>
          <ChevronDown
            className={cn("h-5 w-5 text-gray-500 transition-transform duration-200", isOpen && "transform rotate-180")}
          />
        </div>
      </button>

      <div className={cn("overflow-hidden transition-all duration-300 ease-in-out", isOpen ? "max-h-96" : "max-h-0")}>
        <div className="p-4 pt-0 border-t border-gray-100">
          <ul className="space-y-2">
            {items.map((item, index) => (
              <li key={index} className="text-sm">
                <div className="flex items-center justify-between">
                  <span>{item.title}</span>
                  {item.type && <span className="text-xs text-gray-500">{item.type}</span>}
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}
