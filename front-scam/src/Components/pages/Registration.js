import React, { useState, useEffect } from "react";
import axios from "../../utils/axios";
import { FaUser, FaLock, FaEnvelope, FaCalendarAlt, FaEye, FaEyeSlash, FaCheckCircle, FaTimesCircle } from "react-icons/fa";

const Registration = () => {
  const [formData, setFormData] = useState({
    name: "",
    dob: "",
    email: "",
    password: "",
  });
  const [message, setMessage] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [countdown, setCountdown] = useState(3);
  const [showModal, setShowModal] = useState(false);
  const [isError, setIsError] = useState(false);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const res = await axios.post("/register", formData, {
        headers: {
          "Content-Type": "application/json",
        },
        withCredentials: true,
      });
      setMessage(res.data.message);
      setFormData({
        name: "",
        dob: "",
        email: "",
        password: "",
      });
      setIsError(false);
      setShowModal(true);
    } catch (error) {
      console.error("Registration error:", error.response?.data);
      setMessage(error.response?.data?.error || "Registration failed");
      setIsError(true);
      setShowModal(true);
    }

    let timer = 3;
    setCountdown(timer);
    const interval = setInterval(() => {
      timer--;
      setCountdown(timer);
      if (timer === 0) {
        clearInterval(interval);
        window.location.href = "/login";
      }
    }, 1000);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-r from-blue-900 to-blue-700 p-6">
      <div className="bg-white shadow-lg rounded-lg overflow-hidden flex flex-col md:flex-row max-w-4xl w-full">
        <div className="hidden md:flex w-1/2 bg-blue-900 text-white flex-col items-center justify-center p-8">
          <h2 className="text-3xl font-bold">WELCOME</h2>
          <p className="text-sm text-center mt-2">Scam Awareness Portal</p>
          <p className="text-sm text-center mt-2">Stay informed, stay safe. Learn how to identify and avoid online scams.</p>
        </div>

        <div className="w-full md:w-1/2 p-8">
          <h2 className="text-3xl font-bold text-gray-800 mb-6 text-center">Register</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center border border-gray-300 rounded-lg p-2 transition duration-300 hover:border-blue-500 hover:bg-gray-100">
              <FaUser className="text-blue-600 mr-3" />
              <input 
                type="text" 
                name="name" 
                value={formData.name} 
                onChange={(e) => handleChange({ 
                  target: { 
                    name: "name", 
                    value: e.target.value
                      .toLowerCase()
                      .replace(/\b\w/g, (char) => char.toUpperCase()) 
                  } 
                })} 
                placeholder="User Name" 
                className="w-full p-3 focus:ring-2 focus:ring-blue-400 border-none outline-none" 
                required 
              />

            </div>
            <div className="flex items-center border border-gray-300 rounded-lg p-2 transition duration-300 hover:border-blue-500 hover:bg-gray-100">
              <FaCalendarAlt className="text-blue-600 mr-3" />
              <input 
                type="date" 
                name="dob" 
                value={formData.dob} 
                onChange={handleChange} 
                className="w-full p-3 focus:ring-2 focus:ring-blue-400 border-none outline-none" 
                required 
              />
            </div>
            <div className="flex items-center border border-gray-300 rounded-lg p-2 transition duration-300 hover:border-blue-500 hover:bg-gray-100">
              <FaEnvelope className="text-blue-600 mr-3" />
              <input 
                type="email" 
                name="email" 
                value={formData.email} 
                onChange={(e) => handleChange({ 
                  target: { 
                    name: "email", 
                    value: e.target.value.toLowerCase() 
                  } 
                })} 
                placeholder="Email" 
                className="w-full p-3 focus:ring-2 focus:ring-blue-400 border-none outline-none" 
                required 
              />

            </div>
            <div className="flex items-center border border-gray-300 rounded-lg p-2 transition duration-300 hover:border-blue-500 hover:bg-gray-100">
              <FaLock className="text-blue-600 mr-3" />
              <input 
                type={showPassword ? "text" : "password"} 
                name="password" 
                value={formData.password} 
                onChange={handleChange} 
                placeholder="Password" 
                className="w-full p-3 focus:ring-2 focus:ring-blue-400 border-none outline-none" 
                required 
              />
              <button type="button" onClick={() => setShowPassword(!showPassword)} className="ml-2">
                {showPassword ? <FaEyeSlash className="text-blue-600" /> : <FaEye className="text-blue-600" />}
              </button>
            </div>
            <button 
              type="submit" 
              className="w-full bg-blue-500 text-white p-3 rounded-lg hover:bg-blue-600 transition duration-300"
            >
              Register
            </button>
            <p className="text-center mt-4">
              Already have an account? <a href="/Login" className="text-blue-500 hover:underline">Log In</a>
            </p>
          </form>
        </div>
      </div>


      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center">
          <div className="bg-white p-6 rounded-lg shadow-lg text-center">
            {isError ? (
              <FaTimesCircle className="text-red-500 text-4xl mx-auto" />
            ) : (
              <FaCheckCircle className="text-green-500 text-4xl mx-auto" />
            )}
            <p className={`text-lg font-bold mt-4 ${isError ? 'text-red-600' : 'text-green-600'}`}>{message}</p>
            <p className="text-gray-600">Redirecting login page in {countdown}s...</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default Registration;
