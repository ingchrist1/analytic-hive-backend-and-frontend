"use client";
import { useState, useEffect } from "react";
import Image from "next/image";

import { X} from "lucide-react";
import { FaLinkedin } from "react-icons/fa";
import { FaTwitter } from "react-icons/fa";
import { FaFacebook } from "react-icons/fa";
import { FaSquareWhatsapp } from "react-icons/fa6";
import { FaSquareInstagram } from "react-icons/fa6";
import { FaYoutube } from "react-icons/fa";
const ThankYou = () => {
  const [popUp, setPopUp] = useState(false);
  const shareText = encodeURIComponent(
    "I just registered for free weekly tech sessions with Analytix Hive! Join me: "
  );
  const shareUrl = encodeURIComponent(window.location.href);

  useEffect(() => {
    const timer = setTimeout(() => {
      setPopUp(true);
    }, 1500);
    return () => clearTimeout(timer);
  }, []);

  return (
    <>
      <div
        className={`text-center transition duration-300 ${
          popUp ? "blur-md" : ""
        }`}
      >
        <Image src="/assets/Analytix Hive Logo(transparent).png" alt="logo" className="m-auto w-[200px]" />

        <div className="flex justify-around items-center">
          <Image src="/assets/undraw_super-thank-you_flq2.png" alt="thank you" className="w-[30%]" />
          <span>
            <h1 className="text-3xl my-3">Thank you for registering!</h1>
            <p className="w-[80%] m-auto">
              We appreciate your interest in
              <span className="font-bold text-[#061c2d]"> Analytix </span>
              <span className="font-bold text-amber-400">Hive. </span>
              You're one step closer to enhancing your tech skills with us!
            </p>
          </span>
        </div>
        <footer className="bg-gray-200 w-full flex justify-between items-center">
          <p className="mx-4 text-gray-800 text-xs">All Rights Reserved 2025</p>
          <span className="flex justify-between items-center my-1 mx-4 w-36">
                    <i className="text-xl text-gray-600">
                      <a href="https://www.facebook.com/profile.php?id=61573533484302">
                        <FaFacebook />
                      </a>
                    </i>
                    <i className="text-xl text-gray-600">
                      <a href="https://www.instagram.com/analytixhive/">
                        <FaSquareInstagram />
                      </a>
                    </i>
                    <i className="text-xl text-gray-600">
                      <a href="https://www.linkedin.com/company/analytix-hive">
                        <FaLinkedin />
                      </a>
                    </i>
                    <i className="text-xl text-gray-600">
                      <a href="https://x.com/Analytix_Hive">
                        <FaTwitter />
                      </a>
                    </i>
                    <i className="text-xl text-gray-600">
                      <a href="http://www.youtube.com/@AnalytixHive">
                        <FaYoutube />
                      </a>
                    </i>
                  </span>
        </footer>
      </div>

      {popUp && (
        <div className="fixed inset-0 flex items-center justify-center">
          <div className="bg-white w-[90%] md:w-1/3 p-6 rounded-lg shadow-lg relative">
            {/* Close Button */}
            <button
              onClick={() => setPopUp(false)}
              className="absolute top-3 right-3 text-gray-600 hover:text-gray-900"
            >
              <X size={20} className="cursor-pointer" />
            </button>

            <h2 className="text-xl font-bold text-[#061c2d] mb-3">
              One more thing!
            </h2>
            <p className="text-sm text-gray-700 mb-2">
              Don't hide this update from your friends! Share this link so they
              can grab this rare opportunity too.
            </p>

            {/* Social Media Share Buttons */}
            <div className="flex gap-4 mt-3">
              <a
                href={`https://wa.me/?text=${shareText}${shareUrl}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-green-500 hover:scale-110 transition"
              >
                <FaSquareWhatsapp size={28} />
              </a>

              <a
                href={`https://www.facebook.com/sharer/sharer.php?u=${shareUrl}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <FaFacebook
                  size={24}
                  className="text-blue-600 hover:scale-110 transition"
                />
              </a>

              <a
                href={`https://twitter.com/intent/tweet?text=${shareText}&url=${shareUrl}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-400 hover:scale-110 transition"
              >
                <FaTwitter size={28} />
              </a>

              <a
                href={`https://www.linkedin.com/shareArticle?mini=true&url=${shareUrl}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-700 hover:scale-110 transition"
              >
                <FaLinkedin size={28} />
              </a>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default ThankYou;
