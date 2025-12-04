import React, { useState, useEffect } from "react";
import axios from "../../utils/axios";
import Modal from "./Modal";
import { useNavigate } from "react-router-dom";
import { FiMail, FiPaperclip, FiAlertCircle } from "react-icons/fi";

const ContactUs = () => {
  const [formData, setFormData] = useState({
    message: "",
    attachment: null,
    fileName: ""
  });
  const [isLoading, setIsLoading] = useState(false);
  const [response, setResponse] = useState({
    show: false,
    message: "",
    isSuccess: false
  });
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  // Check user authentication
  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await axios.get("/profile", { withCredentials: true });
        setUser(res.data);
      } catch (error) {
        setUser(null);
        navigate("/login");
      }
    };

    fetchUser();
  }, [navigate]);

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Validate file type
    const validTypes = ["image/jpeg", "image/png", "application/pdf"];
    if (!validTypes.includes(file.type)) {
      setResponse({
        show: true,
        message: "Invalid file type. Only JPG, PNG, and PDF allowed.",
        isSuccess: false
      });
      return;
    }

    // Validate file size (5MB max)
    if (file.size > 5 * 1024 * 1024) {
      setResponse({
        show: true,
        message: "File size exceeds 5MB limit.",
        isSuccess: false
      });
      return;
    }

    // Read file as base64
    const reader = new FileReader();
    reader.onloadend = () => {
      setFormData(prev => ({
        ...prev,
        attachment: reader.result,
        fileName: file.name
      }));
    };
    reader.readAsDataURL(file);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    // Validate form
    if (!formData.message.trim()) {
      setResponse({
        show: true,
        message: "Please enter your message",
        isSuccess: false
      });
      setIsLoading(false);
      return;
    }

    try {
      const response = await axios.post("/contact", formData, {
        withCredentials: true,
        headers: {
          "Content-Type": "application/json"
        }
      });

      setResponse({
        show: true,
        message: response.data.message || "Your message has been sent successfully!",
        isSuccess: true
      });

      // Reset form on success
      if (response.status === 200) {
        setFormData({
          message: "",
          attachment: null,
          fileName: ""
        });
      }
    } catch (error) {
      console.error("Contact submission error:", error);
      setResponse({
        show: true,
        message: error.response?.data?.message || "Failed to send your message. Please try again.",
        isSuccess: false
      });
    } finally {
      setIsLoading(false);
    }
  };

  const removeAttachment = () => {
    setFormData(prev => ({
      ...prev,
      attachment: null,
      fileName: ""
    }));
  };

  if (!user) {
    return (
      <div className="text-center py-8">
        <div className="inline-flex items-center text-red-500">
          <FiAlertCircle className="mr-2" />
          <span>Redirecting to login page...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto p-6 bg-white rounded-lg shadow-md">
      <div className="text-center mb-6">
        <FiMail className="mx-auto text-4xl text-blue-500 mb-2" />
        <h2 className="text-2xl font-bold text-gray-800">Contact Us</h2>
        <p className="text-gray-600">We'd love to hear from you</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="message" className="block text-sm font-medium text-gray-700 mb-1">
            Your Message *
          </label>
          <textarea
            id="message"
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            rows="5"
            value={formData.message}
            onChange={(e) => setFormData({...formData, message: e.target.value})}
            required
            placeholder="Type your message here..."
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Attachment (Optional)
          </label>
          {formData.attachment ? (
            <div className="flex items-center justify-between p-2 border border-gray-300 rounded-md bg-gray-50">
              <span className="truncate flex-1">
                <FiPaperclip className="inline mr-2" />
                {formData.fileName}
              </span>
              <button
                type="button"
                onClick={removeAttachment}
                className="text-red-500 hover:text-red-700 ml-2"
              >
                Remove
              </button>
            </div>
          ) : (
            <div className="flex items-center">
              <label className="cursor-pointer bg-gray-100 hover:bg-gray-200 px-4 py-2 rounded-md border border-gray-300 transition duration-200">
                <FiPaperclip className="inline mr-2" />
                Choose File
                <input
                  type="file"
                  accept=".jpg,.jpeg,.png,.pdf"
                  onChange={handleFileChange}
                  className="hidden"
                />
              </label>
              <span className="ml-2 text-sm text-gray-500">Max 5MB (JPG, PNG, PDF)</span>
            </div>
          )}
        </div>

        <button
          type="submit"
          disabled={isLoading}
          className={`w-full py-3 px-4 rounded-md text-white font-medium transition duration-200 ${
            isLoading ? "bg-blue-400 cursor-not-allowed" : "bg-blue-600 hover:bg-blue-700"
          }`}
        >
          {isLoading ? "Sending..." : "Send Message"}
        </button>
      </form>

      {response.show && (
        <Modal
          message={response.message}
          onClose={() => setResponse({...response, show: false})}
          isSuccess={response.isSuccess}
        />
      )}
    </div>
  );
};

export default ContactUs;