import React, { useState, useEffect } from "react";
import axios from "../../utils/axios";
import { useNavigate } from "react-router-dom";
import Modal from "./Modal"; // Import the Modal component

const scamTypes = [
  "Investment",
  "Romance scams",
  "Product and service scams",
  "Threats and extortion scams",
  "Jobs and employment scams",
  "Unexpected money",
  "Phishing",
  "Buying or selling scams",
  "Other",
];

const ReportScam = () => {
  const [scamType, setScamType] = useState("");
  const [description, setDescription] = useState("");
  const [scamDate, setScamDate] = useState("");
  const [proof, setProof] = useState(null);
  const [message, setMessage] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    axios
      .get("/profile", { withCredentials: true })
      .then((res) => setUser(res.data))
      .catch(() => {
        setUser(null);
        navigate("/login");
      });
  }, [navigate]);

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const validTypes = [
        "image/jpeg", // .jpg, .jpeg
        "video/mp4",   // .mp4
        "audio/mpeg",  // .mp3
        "application/pdf", // .pdf
      ];
      const fileSizeMB = file.size / (1024 * 1024);
      
      // Check if the file type is valid
      if (!validTypes.includes(file.type)) {
        setMessage("Invalid file type. Only .jpg, .jpeg, .mp4, .mp3, and .pdf are allowed.");
        setShowModal(true);
        setIsSuccess(false);
        return;
      }
      
      // Check file size
      if (fileSizeMB > 10) {
        setMessage("File size exceeds 10MB limit.");
        setShowModal(true);
        setIsSuccess(false);
        return;
      }
  
      const reader = new FileReader();
      reader.readAsDataURL(file);
      reader.onloadend = () => {
        setProof(reader.result);
      };
    }
  };

  const handleDateChange = (e) => {
    const selectedDate = new Date(e.target.value);
    const currentDate = new Date();

    if (selectedDate > currentDate) {
      setMessage("Scam date cannot be in the future.");
      setShowModal(true);
      setIsSuccess(false);
      setScamDate(""); // Clear the input
    } else {
      setScamDate(e.target.value);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!scamType || !description || !scamDate || !proof) {
      setMessage("All fields, including proof, are required!");
      setShowModal(true);
      setIsSuccess(false);
      return;
    }

    const reportData = {
      scam_type: scamType,
      description,
      scam_date: scamDate,
      proof, // Base64 encoded file
    };

    try {
      const response = await axios.post(
        "/scam-reports",
        reportData,
        { withCredentials: true }
      );
      setMessage(response.data.message);
      setIsSuccess(true);
      setShowModal(true);
      setScamType("");
      setDescription("");
      setScamDate("");
      setProof(null);
    } catch (error) {
      setMessage("Failed to submit scam report");
      setIsSuccess(false);
      setShowModal(true);
      console.error("Error submitting scam report:", error);
    }
  };

  return (
    <div className="max-w-md mx-auto p-6 bg-white shadow-md rounded-md">
      {user ? (
        <>
          <h2 className="text-xl font-semibold mb-4">Submit a Scam Report</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium">Scam Type</label>
              <select
                className="w-full p-2 border rounded"
                value={scamType}
                onChange={(e) => setScamType(e.target.value)}
                required
              >
                <option value="">Select a scam type</option>
                {scamTypes.map((type, index) => (
                  <option key={index} value={type}>
                    {type}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium">Description</label>
              <textarea
                className="w-full p-2 border rounded"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                required
              ></textarea>
            </div>

            <div>
              <label className="block text-sm font-medium">Scam Date</label>
              <input
                type="date"
                className="w-full p-2 border rounded"
                value={scamDate}
                onChange={handleDateChange}
                min="2010-01-01" // Set min date to January 1, 2010
                max={new Date().toISOString().slice(0, 10)} // Set max to current date
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium">Proof (Required)</label>
              <input type="file" accept="image/*,video/*,audio/*,.pdf,.doc,.docx" onChange={handleFileChange} required />
            </div>

            <button
              type="submit"
              className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
            >
              Submit Report
            </button>
          </form>

          {/* Render the Modal */}
          {showModal && (
            <Modal
              message={message}
              onClose={() => setShowModal(false)}
              isSuccess={isSuccess}
            />
          )}
        </>
      ) : (
        <p className="text-center text-red-500">Redirecting to login page...</p>
      )}
    </div>
  );
};

export default ReportScam;