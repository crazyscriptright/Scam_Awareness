import { FaChartLine } from 'react-icons/fa'; // Import the chosen icon
import React, { useState } from "react";
import { HashLink } from "react-router-hash-link";
import { useNavigate } from "react-router-dom";
import {
  FaChartBar,
  FaShieldAlt,
  FaUsers,
  FaClipboardList,
  FaSignOutAlt,
} from "react-icons/fa";
import axios from "../../utils/axios";
import WithAuth from "../hooks/WithAuth"; // Corrected import path
import "tailwindcss/tailwind.css";

const AdminNavbar = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const [user, setUser] = useState({ name: "User", profilePic: "" });
  const navigate = useNavigate();

  const toggleSidebar = () => {
    setIsOpen(!isOpen);
  };

  const closeSidebar = () => {
    setIsOpen(false);
  };

  const handleLogout = () => {
    setShowLogoutModal(true);
  };

  const confirmLogout = () => {
    axios
      .post("/logout", {}, { withCredentials: true })
      .then(() => {
        setUser({ name: "User", profilePic: "" });
        setShowLogoutModal(false);
        setTimeout(() => {
          navigate("/"); // Redirect to home page
        }, 500); // Wait for 3 seconds
      })
      .catch((err) => console.error("Logout error", err));
  };

  const cancelLogout = () => {
    setShowLogoutModal(false);
  };

  return (
    <div className="flex">
      {/* Overlay for sidebar */}
      <div
        className={`fixed inset-0 bg-gray-800 bg-opacity-50 z-40 ${
          isOpen ? "block" : "hidden"
        }`}
        onClick={closeSidebar}
      ></div>

      {/* Sidebar */}
      <div
        className={`fixed inset-y-0 left-0 bg-gray-900 text-white w-64 z-50 transform ${
          isOpen ? "translate-x-0" : "-translate-x-full"
        } transition-transform duration-300 ease-in-out`}
      >
        <div className="p-4">
          <button className="text-white" onClick={toggleSidebar}>
            <svg
              className="w-6 h-6"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M6 18L18 6M6 6l12 12"
              ></path>
            </svg>
          </button>
          <HashLink
            smooth
            to="#home"
            className="text-2xl font-bold mt-4 block"
            onClick={closeSidebar}
          >
            Admin Panel
          </HashLink>
        </div>

        {/* Navigation links */}
        <nav className="mt-10">
        <HashLink
          smooth
          to="#User_Metrics"
          className="block py-2.5 px-4 rounded transition duration-200 hover:bg-gray-700"
          onClick={closeSidebar}
        >
          <FaChartLine className="inline-block mr-2 text-blue-500" /> User Metrics
        </HashLink>
          <HashLink
            smooth
            to="#Analytics"
            className="block py-2.5 px-4 rounded transition duration-200 hover:bg-gray-700"
            onClick={closeSidebar}
          >
            <FaChartBar className="inline-block mr-2 text-blue-500" /> Analytics
          </HashLink>
          <HashLink
            smooth
            to="#Review"
            className="block py-2.5 px-4 rounded transition duration-200 hover:bg-gray-700"
            onClick={closeSidebar}
          >
            <FaShieldAlt className="inline-block mr-2 text-red-500" /> Review
          </HashLink>
          <HashLink
            smooth
            to="#Contact_Us"
            className="block py-2.5 px-4 rounded transition duration-200 hover:bg-gray-700"
            onClick={closeSidebar}
          >
            <FaClipboardList className="inline-block mr-2 text-yellow-500" />{" "}
            Complaints
          </HashLink>
          <HashLink
            smooth
            to="#User_Management"
            className="block py-2.5 px-4 rounded transition duration-200 hover:bg-gray-700"
            onClick={closeSidebar}
          >
            <FaUsers className="inline-block mr-2 text-green-500" /> User
            Management
          </HashLink>

          {/* Logout Button */}
          <button
            onClick={handleLogout}
            className="flex items-center space-x-2 p-2 hover:bg-gray-700 w-full text-red-500"
          >
            <FaSignOutAlt />
            <span>Logout</span>
          </button>
        </nav>
      </div>

      {/* Sidebar Toggle Button */}
      <div className="flex-1 p-4">
        <button className="text-gray-900" onClick={toggleSidebar}>
          <svg
            className="w-6 h-6"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M4 6h16M4 12h16m-7 6h7"
            ></path>
          </svg>
        </button>
      </div>

      {/* Logout Modal */}
      {showLogoutModal && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
          <div className="bg-white p-6 rounded-lg shadow-lg w-80">
            <p className="text-center text-gray-800">
              You are about to logout...
            </p>
            <div className="flex justify-center mt-4">
              <button
                onClick={confirmLogout}
                className="bg-red-500 text-white px-4 py-2 rounded mr-2"
              >
                Confirm
              </button>
              <button
                onClick={cancelLogout}
                className="bg-gray-500 text-white px-4 py-2 rounded"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default WithAuth(AdminNavbar);