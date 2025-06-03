"use client";
import Slider from "react-slick";
import "slick-carousel/slick/slick.css";
import "slick-carousel/slick/slick-theme.css";
import { X } from "lucide-react";
import Form from "../components/Form";
import { useState } from "react";
const SecondSection = ({ classesRef }) => {
  const [boxIsOpen, setBoxIsOpen] = useState(false);
  const settings = {
    dots: false,
    infinite: true,
    speed: 500,
    slidesToShow: 1,
    slidesToScroll: 1,
    autoplay: true,
    autoplaySpeed: 2000,
    arrows: false,
  };
  return (
    <main
      ref={classesRef}
      className="w-[90%] mx-auto mb-30 rounded-lg flex flex-col lg:flex-row justify-between items-center"
    >
      <aside className="w-[90%] lg:w-[40%] m-auto">
        <Slider {...settings}>
          <div>
            <img src="/assets/Course app-pana.png" alt="image" />
          </div>
          <div>
            <img src="/assets/Online learning-cuate.png" alt="image" />
          </div>
          <div>
            <img src="/assets/Online learning-bro.png" alt="image" />
          </div>
          <div>
            <img src="/assets/Online learning-pana.png" alt="image" />
          </div>
        </Slider>
      </aside>
      <div className="text-center w-[90%] lg:w-[55%] bg-amber-200 rounded-xl text-[#061c2d]">
        <h1 className="capitalize font-semibold text-2xl my-5">
          Join our free weekly classes on AI & data topics
        </h1>
        <p className="my-2 w-[96%] m-auto">
          While we're putting on the final polish, why not jump in early?  
          Enjoy <span>exclusive access to our FREE Data Analysis course</span> when you join the waitlist.  
          Whether you're leveling up your career or just curious to see what tech's all about,  
          come as you are and join the ride.
        </p>

        <button
          onClick={() => setBoxIsOpen(true)}
          className=" bg-amber-300 w-64 h-12 my-10 m-auto rounded-lg px-3 font-semibold text-[#061c2d] shadow-lg cursor-pointer"
        >
          Yes! I'm Interested
        </button>
      </div>

      {/* pop up */}
      {boxIsOpen && (
        <div className="fixed inset-0 flex items-center justify-center">
          <div className="bg-white w-[90%] lg:w-1/2  p-6 rounded-lg shadow-lg relative">
            {/* Close Button */}
            <button
              onClick={() => setBoxIsOpen(false)}
              className="absolute top-3 right-3 text-gray-600 hover:text-gray-900"
            >
              <X size={20} className="cursor-pointer" />
            </button>

            <Form />
          </div>
        </div>
      )}
    </main>
  );
};

export default SecondSection;
