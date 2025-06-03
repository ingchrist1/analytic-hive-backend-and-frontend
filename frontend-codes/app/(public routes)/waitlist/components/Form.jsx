"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { db, collection, addDoc } from "../../../firebaseConfig";

const Form = () => {
  const [formData, setFormData] = useState({ name: "", email: "" });
  const [message, setMessage] = useState("");
  const router = useRouter()

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("Submitting...");

    try {
      await addDoc(collection(db, "waitlist"), {
        name: formData.name,
        email: formData.email,
        timestamp: new Date(),
      });

      setMessage("Form submitted successfully!");
      router.push("/thankyou")
      setFormData({ name: "", email: "" });
    } catch (error) {
      setMessage("Error submitting form.");
      console.error("Error:", error);
    }
  };
  return (
    <div>
      <form
        onSubmit={handleSubmit}
        className="bg-white grid col-3 gap-3 w-full my-20 shadow-xl rounded-lg"
      >
        <input
          type="text"
          name="name"
          placeholder="Full name"
          className="w-[90%] h-12 mt-16 m-auto rounded-lg px-3 shadow-lg"
          value={formData.name}
          onChange={handleChange}
          required
        />
        <input
          type="email"
          name="email"
          placeholder="Email address"
          className="w-[90%] h-12 my-2 m-auto rounded-lg px-3 shadow-lg"
          value={formData.email}
          onChange={handleChange}
          required
        />
        <button
          type="submit"
          className="bg-amber-300 w-[90%] h-12 mt-2 mb-16 m-auto rounded-lg px-3 font-semibold text-[#061c2d] shadow-lg cursor-pointer"
        >
          Join Waitlist
        </button>
      </form>
      <p className="text-center">{message}</p>
    </div>
  );
};

export default Form;
