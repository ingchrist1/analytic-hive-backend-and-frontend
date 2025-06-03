"use client";
import { useState } from 'react';
import logo from '../../../../public/assets/Analytix Hive Logo(transparent).png'
import Image from 'next/image';
const Navbar = ({scrollToSection, waitlistRef, classesRef, contactRef}) => {
  const [boxIsOpen, setBoxIsOpen] = useState(false)
  return (
    <main className="w-full">
    <div className="max-w-[1440px]  mx-auto ">
      <header className="flex justify-between items-center w-full py-4">
        <i className="mx-2">
          <Image
            src="/assets/Analytix Hive Logo(transparent).png"
            alt="logo"
            className="w-[100px]"
            width={100}
            height={100}
          />
        </i>
  
        {/* Mobile Navigation */}
   <div className='flex gap-2 items-center'>
          <li
            onClick={() => scrollToSection(waitlistRef)}
            className="bg-amber-300 p-2 rounded-md  block md:hidden list-none text-[#061c2d] font-semibold cursor-pointer my-5"
          >
            Join Waitlist
            
          </li>
          {boxIsOpen && (
            <div className="bg-blue-800 mt-2 space-y-2 p-2 rounded-md block md:hidden ">
              <li
                onClick={() => scrollToSection(classesRef)}
                className="shadow-lg p-2 rounded-md bg-white text-black"
              >
                Free Classes
              </li>
              <li
                onClick={() => scrollToSection(contactRef)}
                className="shadow-lg p-2 rounded-md bg-white text-black"
              >
                Contact Us
              </li>
            </div>
          )}
          <span
          className="mx-3 block md:hidden cursor-pointer text-lg"
          onClick={() => setBoxIsOpen(!boxIsOpen)}
        >
          ☰
        </span>
        </div>
         
      
        {/* Desktop Navigation */}
        <nav className="hidden md:flex justify-around items-center list-none text-[#061c2d] font-semibold cursor-pointer my-5 gap-12">
          <li
            onClick={() => scrollToSection(waitlistRef)}
            className="hover:bg-amber-300  hover:p-2 hover:rounded-md hover:text-white transition"
          >
            Join Waitlist
          </li>
          <li
            onClick={() => scrollToSection(classesRef)}
            className="hover:shadow-lg hover:p-2 hover:rounded-md transition"
          >
            Free Classes
          </li>
          <li
            onClick={() => scrollToSection(contactRef)}
            className="hover:shadow-lg hover:p-2 hover:rounded-md transition"
          >
            Contact Us
          </li>
        </nav>
  
    
      </header>
    </div>
  </main>
  );
}

export default Navbar