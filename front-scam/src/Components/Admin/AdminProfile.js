import React, { useState, useEffect, useRef } from "react";
import axios from "../../utils/axios";
import { FaUser, FaKey, FaSignOutAlt, FaCamera, FaUserCircle, FaEye, FaEyeSlash } from "react-icons/fa";
import { useNavigate } from "react-router-dom";
import WithAuth from "../hooks/WithAuth";


const AdminProfile = () => {
  const [user, setUser] = useState({ name: "User", profilePic: "" });
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [isPasswordModalOpen, setIsPasswordModalOpen] = useState(false);
  const [isProfileModalOpen, setIsProfileModalOpen] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [confirmPasswordVisible, setConfirmPasswordVisible] = useState(false);
  const [logoutMessage, setLogoutMessage] = useState(null);
  const dropdownRef = useRef(null);
  const navigate = useNavigate();

  // Fetch Admin Profile and Picture
  useEffect(() => {
    axios.get("/profile-picture", { withCredentials: true })
    .then((res) => {
        if (res.data) {
          setUser({
            name: res.data.name || "User",
            profilePic: res.data.profile_picture 
              ? `data:image/png;base64,${res.data.profile_picture}`
              : "",
          });
        }
      })
      .catch((err) => console.error("Profile fetch error", err));
  }, []);

  // Handle Logout
  const handleLogout = () => {
    axios.post("/logout", {}, { withCredentials: true })
    .then(() => {
        setUser({ name: "User", profilePic: "" });
        setLogoutMessage("You are being logged out...");
        setTimeout(() => navigate("/"), 3000);
      })
      .catch((err) => console.error("Logout error", err));
  };

  // Handle Password Update
  const handlePasswordChange = () => {
    if (newPassword !== confirmPassword) {
      alert("Passwords do not match!");
      return;
    }

    axios.post("/update-password", { newPassword }, { withCredentials: true })
    .then(() => {
        alert("Password updated successfully!");
        setNewPassword("");
        setConfirmPassword("");
        setIsPasswordModalOpen(false);
      })
      .catch((err) => console.error("Password update error", err));
  };

  // Handle Profile Picture Update
  const handleProfilePictureChange = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onloadend = () => {
      const base64Data = reader.result.split(",")[1]; // Get only the Base64 part

      axios.post("/profile-picture", { profile_picture: base64Data }, { withCredentials: true })
      .then(() => {
          setUser(prev => ({
            ...prev,
            profilePic: `data:image/png;base64,${base64Data}`
          }));
          alert("Profile picture updated successfully!");
          setIsProfileModalOpen(false);
        })
        .catch((err) => console.error("Profile picture update error", err));
    };
  };

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Profile Button */}
      <button
        onClick={() => setDropdownOpen(!dropdownOpen)}
        className="flex items-center space-x-2 bg-gray-800 text-white p-2 rounded-full"
      >
        {user.profilePic ? (
          <img
            src={user.profilePic}
            alt="Profile"
            className="w-8 h-8 rounded-full"
          />
        ) : (
          <FaUserCircle className="w-8 h-8 text-white" />
        )}
      </button>

      {/* Dropdown Menu */}
      {dropdownOpen && (
        <div className="absolute right-0 mt-2 w-56 bg-white shadow-lg rounded-lg p-2">
          <div className="px-3 py-2 text-gray-700 font-semibold border-b">
            Hello, {user.name}!
          </div>

          <button
            onClick={() => setIsPasswordModalOpen(true)}
            className="flex items-center space-x-2 p-2 hover:bg-gray-100 w-full"
          >
            <FaKey className="text-green-500" />
            <span>Change Password</span>
          </button>

          <button
            onClick={() => setIsProfileModalOpen(true)}
            className="flex items-center space-x-2 p-2 hover:bg-gray-100 w-full"
          >
            <FaCamera className="text-purple-500" />
            <span>Update Picture</span>
          </button>

          <button
            onClick={handleLogout}
            className="flex items-center space-x-2 p-2 hover:bg-gray-100 w-full text-red-500"
          >
            <FaSignOutAlt />
            <span>Logout</span>
          </button>
        </div>
      )}

      {/* Password Update Modal */}
      {isPasswordModalOpen && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white p-6 rounded-lg shadow-lg w-80">
            <h2 className="text-xl font-semibold mb-4">Change Password</h2>
            <input
              type={passwordVisible ? "text" : "password"}
              className="w-full px-3 py-2 border rounded focus:outline-none focus:ring mb-2"
              placeholder="Enter new password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
            <button
              type="button"
              onClick={() => setPasswordVisible(!passwordVisible)}
              className="text-sm text-blue-500 mb-2"
            >
              {passwordVisible ? <FaEyeSlash /> : <FaEye />} View Password
            </button>
            <input
              type={confirmPasswordVisible ? "text" : "password"}
              className="w-full px-3 py-2 border rounded focus:outline-none focus:ring mb-2"
              placeholder="Confirm new password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
            <button
              type="button"
              onClick={() => setConfirmPasswordVisible(!confirmPasswordVisible)}
              className="text-sm text-blue-500 mb-4"
            >
              {confirmPasswordVisible ? <FaEyeSlash /> : <FaEye />} View Password
            </button>
            <div className="flex justify-end mt-4">
              <button
                className="bg-gray-300 px-3 py-1 rounded mr-2"
                onClick={() => setIsPasswordModalOpen(false)}
              >
                Cancel
              </button>
              <button
                onClick={handlePasswordChange}
                className="bg-green-500 text-white px-3 py-1 rounded hover:bg-green-600"
              >
                Update
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Profile Picture Update Modal */}
      {isProfileModalOpen && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white p-6 rounded-lg shadow-lg w-80">
            <h2 className="text-xl font-semibold mb-4">Update Profile Picture</h2>
            <input
              type="file"
              accept="image/*"
              className="w-full text-sm text-gray-600"
              onChange={handleProfilePictureChange}
            />
            <div className="flex justify-end mt-4">
              <button
                className="bg-gray-300 px-3 py-1 rounded mr-2"
                onClick={() => setIsProfileModalOpen(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Logout Message */}
      {logoutMessage && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white p-6 rounded-lg shadow-lg w-80">
            <p>{logoutMessage}</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default WithAuth(AdminProfile);