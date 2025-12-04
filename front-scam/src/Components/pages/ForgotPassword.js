import React, { useState } from "react";
import axios from "../../utils/axios";
import { FaEnvelope, FaCalendarAlt, FaLock, FaEye, FaEyeSlash, FaCheckCircle, FaTimesCircle } from "react-icons/fa";

const ForgotPassword = () => {
  const [formData, setFormData] = useState({
    email: "",
    dob: "",
    newPassword: "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const [message, setMessage] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [isError, setIsError] = useState(false);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post("/forgot-password", formData, {
        headers: { "Content-Type": "application/json" },
        withCredentials: true,
      });

      setMessage(res.data.message);
      setIsError(false);
      setShowModal(true);

      setTimeout(() => {
        window.location.href = "/login";
      }, 3000);
    } catch (error) {
      setMessage("Password reset failed. Check your details.");
      setIsError(true);
      setShowModal(true);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-r from-blue-900 to-blue-700 p-6">
      <div className="bg-white shadow-lg rounded-lg overflow-hidden flex flex-col md:flex-row max-w-4xl w-full">
        
        {/* Left Side - Info Panel */}
        <div className="hidden md:flex w-1/2 bg-blue-900 text-white flex-col items-center justify-center p-8">
          <h2 className="text-3xl font-bold">Forgot Password?</h2>
          <p className="text-sm text-center mt-2">Securely reset your password</p>
        </div>

        {/* Right Side - Reset Form */}
        <div className="w-full md:w-1/2 p-8">
          <h2 className="text-3xl font-bold text-gray-800 mb-6 text-center">Reset Password</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center border border-gray-300 rounded-lg p-2 hover:border-blue-500 hover:bg-gray-100">
              <FaEnvelope className="text-blue-600 mr-3" />
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="Registered Email"
                className="w-full p-3 focus:ring-2 focus:ring-blue-400 border-none outline-none"
                required
              />
            </div>
            <div className="flex items-center border border-gray-300 rounded-lg p-2 hover:border-blue-500 hover:bg-gray-100">
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
            <div className="flex items-center border border-gray-300 rounded-lg p-2 hover:border-blue-500 hover:bg-gray-100">
              <FaLock className="text-blue-600 mr-3" />
              <input
                type={showPassword ? "text" : "password"}
                name="newPassword"
                value={formData.newPassword}
                onChange={handleChange}
                placeholder="New Password"
                className="w-full p-3 focus:ring-2 focus:ring-blue-400 border-none outline-none"
                required
              />
              <button type="button" onClick={() => setShowPassword(!showPassword)} className="ml-2">
                {showPassword ? <FaEyeSlash className="text-blue-600" /> : <FaEye className="text-blue-600" />}
              </button>
            </div>
            <button type="submit" className="w-full bg-blue-500 text-white p-3 rounded-lg hover:bg-blue-600 transition duration-300">
              Reset Password
            </button>
            {/* Back to Login */}
            <p className="text-center mt-4">
                Remember your password? <a href="/login" className="text-blue-500 hover:underline">Back to Login</a>
            </p>
          </form>
        </div>
      </div>



      {/* Modal for Status Messages */}
      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center">
          <div className="bg-white p-6 rounded-lg shadow-lg text-center">
            {isError ? (
              <FaTimesCircle className="text-red-500 text-4xl mx-auto" />
            ) : (
              <FaCheckCircle className="text-green-500 text-4xl mx-auto" />
            )}
            <p className={`text-lg font-bold mt-4 ${isError ? 'text-red-600' : 'text-green-600'}`}>{message}</p>
            {isError ? (
              <button className="mt-4 bg-red-500 text-white px-4 py-2 rounded-lg hover:bg-red-600" onClick={() => setShowModal(false)}>Close</button>
            ) : (
              <p className="text-gray-600">Redirecting to login...</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ForgotPassword;
