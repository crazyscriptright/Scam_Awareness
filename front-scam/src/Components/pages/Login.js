import React, { useState, useEffect } from "react";
import axios from "../../utils/axios";
import {
  FaEnvelope,
  FaLock,
  FaEye,
  FaEyeSlash,
  FaCheckCircle,
  FaTimesCircle,
} from "react-icons/fa";
import { useNavigate } from "react-router-dom";

const Login = () => {
  const [formData, setFormData] = useState({ email: "", password: "" });
  const [message, setMessage] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [isError, setIsError] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // Check if user is already logged in via JWT token
    const token = localStorage.getItem('scam_awareness_token');
    const user = JSON.parse(localStorage.getItem('scam_awareness_user') || '{}');
    
    if (token && user.userType !== undefined) {
      const redirectUrl = user.userType === 1 
        ? "/Admin/AdminHome" 
        : user.userType === 2 
        ? "/ExternalResources/ExternalResourcesHome" 
        : "/";
      navigate(redirectUrl);
    }
  }, [navigate]);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post("/signin", formData, {
        headers: { "Content-Type": "application/json" },
      });
  
      // Handle successful login
      setMessage(`Welcome, ${res.data.userName}!`);
      setIsError(false);
      setShowModal(true);
  
      setTimeout(() => {
        navigate(res.data.redirectUrl);
      }, 2000);
    } catch (error) {
      // Handle errors from the backend
      const errorMessage = error.response?.data?.error || "Invalid Credentials. Please try again.";
      setMessage(errorMessage);
      setIsError(true);
      setShowModal(true);
  
      // If the account is banned or inactive, provide a link to contact admin
      if (errorMessage.includes("banned") || errorMessage.includes("not active")) {
        setMessage(
          <>
            {errorMessage} <a href="/ContactUs" className="text-blue-500 hover:underline">Contact Admin</a>
          </>
        );
      }
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-r from-blue-900 to-blue-700 p-6">
      <div className="bg-white shadow-lg rounded-lg overflow-hidden flex flex-col md:flex-row max-w-4xl w-full">
        {/* Left Side: Scam Awareness Portal */}
        <div className="hidden md:flex w-1/2 bg-blue-900 text-white flex-col items-center justify-center p-8">
          <h2 className="text-3xl font-bold">BE AWARE</h2>
          <p className="text-sm text-center mt-2">Protect yourself from scams. Always verify before you trust.</p>
        </div>

        {/* Right Side: Login Form */}
        <div className="w-full md:w-1/2 p-8">
          <h2 className="text-3xl font-bold text-gray-800 mb-6 text-center">Login</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center border border-gray-300 rounded-lg p-2 transition duration-300 hover:border-blue-500 hover:bg-gray-100">
              <FaEnvelope className="text-blue-600 mr-3" />
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={(e) => handleChange({ target: { name: "email", value: e.target.value.toLowerCase() } })}
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
            <button type="submit" className="w-full bg-blue-500 text-white p-3 rounded-lg hover:bg-blue-600 transition duration-300">
              Login
            </button>
          </form>
          <div className="text-center mt-4">
            <a href="/ForgotPassword" className="text-blue-500 hover:underline">Forgot Password?</a>
          </div>
          <p className="text-center mt-2">
            Don't have an account? <a href="/Registration" className="text-blue-500 hover:underline">Sign Up</a>
          </p>
        </div>
      </div>

      {/* Success/Error Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center">
          <div className="bg-white p-6 rounded-lg shadow-lg text-center">
            {isError ? (
              <>
                <FaTimesCircle className="text-red-500 text-4xl mx-auto" />
                <p className="text-lg font-bold mt-4 text-red-600">{message}</p>
                {/* Close Button for Error */}
                <button
                  onClick={() => setShowModal(false)}
                  className="mt-4 bg-red-500 text-white px-4 py-2 rounded-lg hover:bg-red-600 transition"
                >
                  Close
                </button>
              </>
            ) : (
              <>
                <FaCheckCircle className="text-green-500 text-4xl mx-auto animate-bounce" />
                <p className="text-lg font-bold mt-4 text-green-600">{message}</p>
                <p className="text-gray-600">Redirecting...</p>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default Login;
