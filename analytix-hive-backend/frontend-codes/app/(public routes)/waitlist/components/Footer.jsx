import logo from "../../../../public/assets/Analytix Hive Logo.jpg";
import { FaFacebook } from "react-icons/fa";
import { FaSquareInstagram } from "react-icons/fa6";
import { FaLinkedin } from "react-icons/fa";
import { FaTwitter } from "react-icons/fa";
import { FaYoutube } from "react-icons/fa";
import Image from "next/image";
const Footer = ({contactRef}) => {
  return (
    <footer
      ref={contactRef}
      className="md:flex-row flex gap-4 flex-col justify-between mx-auto max-w-[1440px]  items-center "
    >
      <div className=" flex flex-col  items-center">
        <i >
          <Image src="/assets/Analytix Hive Logo.jpg" alt="logo" className="w-[80px] rounded-xl " width={100} height={100} />
        </i>
        <p className="text-[#061c2d] text-sm my-3">
          The Pan-African Tech School
        </p>
      </div>

      <div className="text-[#061c2d] flex flex-col  items-center">
        <h1 className="font-semibold ">Contact Us</h1>
        <p className="text-sm">Email: analytixhive@gmail.com</p>
        <p className="text-sm">Phone: +234-901-603-7991</p>
      </div>

       <div className="flex  flex-col  items-center ">
        <h1 className="text-[#061c2d] font-semibold">Follow Us</h1>
        <span className="flex justify-between items-center my-2 w-32">
          <i className="text-xl text-white">
            <a href="https://www.facebook.com/profile.php?id=61573533484302">
              <FaFacebook />
            </a>
          </i>
          <i className="text-xl text-white">
            <a href="https://www.instagram.com/analytixhive/">
              <FaSquareInstagram />
            </a>
          </i>
          <i className="text-xl text-white">
            <a href="https://www.linkedin.com/company/analytix-hive">
              <FaLinkedin />
            </a>
          </i>
          <i className="text-xl text-white">
            <a href="https://x.com/Analytix_Hive">
              <FaTwitter />
            </a>
          </i>
          <i className="text-xl text-white">
            <a href="http://www.youtube.com/@AnalytixHive">
              <FaYoutube />
            </a>
          </i>
        </span>
      </div> 
    </footer>
  );
};

export default Footer;
