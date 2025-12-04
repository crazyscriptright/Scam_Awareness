import axios from "../../utils/axios";
import { Link } from "react-router-dom";
import React, { useState, useEffect } from "react";
import Navbar from "./Navbar";
import Profile from "../User/Profile"; // Ensure this file exists at ../User/Profile.js
import ReportScam from "../User/ReportScam"; // Ensure this file exists at ../User/ReportScam.js
import WhoWeAre from "./component/WhoWeAre";
import WhatWeDo from "./component/WhatWeDo";
import OurAchievements from "./component/OurAchievements";
import Header from "./component/Header";
import ScamShield from "./component/ScamShield";
import ScamTypesSection from "./component/ScamTypesSection";
import PreventionTipsSection from "./component/PreventionTipsSection";
import Footer from "../User/Footer";
import DynamicBackground from "./component/DynamicBackground"
import ArticleCarousel from "./component/ArticleCarousel"
import ContactUs from "../User/ContactUs";
import {
  FaTrophy,
  FaUsers,
  FaCheckCircle,
  FaUserCircle,
  FaShieldAlt,
  FaExclamationTriangle,
  FaNewspaper,
  FaLock,
  FaArrowRight
} from "react-icons/fa";
import { motion } from "framer-motion";

// Import Lusion-inspired fonts
import "./font.css";

// Enhanced SVG Background Component
const AnimatedBackground = () => (
  <div className="fixed inset-0 overflow-hidden pointer-events-none z-[-1]">
    <svg 
      className="w-full h-full" 
      viewBox="0 0 1000 1000" 
      preserveAspectRatio="none" 
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        {/* Gradient background */}
        <linearGradient id="bg-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#f8fafc" />
          <stop offset="100%" stopColor="#f1f5f9" />
        </linearGradient>
        
        {/* Dot pattern */}
        <pattern 
          id="dot-pattern" 
          x="0" 
          y="0" 
          width="40" 
          height="40" 
          patternUnits="userSpaceOnUse"
        >
          <circle cx="20" cy="20" r="1" fill="#cbd5e1" opacity="0.2" />
        </pattern>
        
        {/* Radial gradients for blobs */}
        <radialGradient id="blob-gradient-1" cx="50%" cy="50%" r="50%" fx="50%" fy="50%">
          <stop offset="0%" stopColor="#2563eb" stopOpacity="0.08" />
          <stop offset="100%" stopColor="#2563eb" stopOpacity="0" />
        </radialGradient>
        
        <radialGradient id="blob-gradient-2" cx="50%" cy="50%" r="50%" fx="50%" fy="50%">
          <stop offset="0%" stopColor="#8b5cf6" stopOpacity="0.08" />
          <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0" />
        </radialGradient>
      </defs>
      
      {/* Background */}
      <rect width="100%" height="100%" fill="url(#bg-gradient)" />
      <rect width="100%" height="100%" fill="url(#dot-pattern)" />
      
      {/* Animated blobs */}
      <motion.circle 
        cx="20%" 
        cy="30%" 
        r="15%" 
        fill="url(#blob-gradient-1)"
        initial={{ opacity: 0 }}
        animate={{
          opacity: [0, 0.1, 0],
          cx: ["20%", "22%", "20%"],
          cy: ["30%", "32%", "30%"]
        }}
        transition={{
          duration: 25,
          repeat: Infinity,
          repeatType: "reverse",
          ease: "easeInOut"
        }}
      />
      
      <motion.circle 
        cx="80%" 
        cy="70%" 
        r="18%" 
        fill="url(#blob-gradient-2)"
        initial={{ opacity: 0 }}
        animate={{
          opacity: [0, 0.1, 0],
          cx: ["80%", "78%", "80%"],
          cy: ["70%", "68%", "70%"]
        }}
        transition={{
          duration: 30,
          repeat: Infinity,
          repeatType: "reverse",
          ease: "easeInOut",
          delay: 10
        }}
      />
    </svg>
    
    {/* Floating gradient blobs (HTML elements for better performance) */}
    <motion.div 
      className="absolute top-1/4 left-1/4 w-96 h-96 rounded-full bg-blue-500 opacity-10 blur-[100px]"
      initial={{ opacity: 0 }}
      animate={{
        opacity: [0, 0.1, 0],
        x: ["-50%", "-45%", "-50%"],
        y: ["-50%", "-55%", "-50%"]
      }}
      transition={{
        duration: 25,
        repeat: Infinity,
        repeatType: "reverse",
        ease: "easeInOut"
      }}
    />
    
    <motion.div 
      className="absolute bottom-1/4 right-1/4 w-96 h-96 rounded-full bg-purple-500 opacity-10 blur-[100px]"
      initial={{ opacity: 0 }}
      animate={{
        opacity: [0, 0.1, 0],
        x: ["50%", "55%", "50%"],
        y: ["50%", "45%", "50%"]
      }}
      transition={{
        duration: 30,
        repeat: Infinity,
        repeatType: "reverse",
        ease: "easeInOut",
        delay: 15
      }}
    />
  </div>
);

const Home = () => {
  const [modalOpen, setModalOpen] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  useEffect(() => {
    const checkAuthentication = () => {
      const user = localStorage.getItem("user");
      setIsAuthenticated(!!user);
    };

    checkAuthentication();
    window.addEventListener("authChange", checkAuthentication);
    return () => {
      window.removeEventListener("authChange", checkAuthentication);
    };
  }, []);

  // Lusion-inspired color palette
  const colors = {
    primary: "#2563eb",       // Vibrant blue
    secondary: "#1e293b",     // Dark slate
    accent: "#f59e0b",        // Amber
    light: "#f8fafc",         // Lightest slate
    dark: "#0f172a",          // Darkest slate
  };

  return (
    <div className="text-gray-900 font-sans antialiased relative overflow-hidden">
      {/* Animated Background */}
      <div>
      <DynamicBackground />
      
      {/* Modern Navbar with Lusion-inspired styling */}
      <Navbar colors={colors} isMenuOpen={isMenuOpen} setIsMenuOpen={setIsMenuOpen} />
      
      {/* Profile positioned absolutely */}
      <div className="absolute top-6 right-6 z-50">
        <Profile colors={colors} />
      </div>

      {/* Hero Section */}
      <div id="home">
        <ScamShield colors={colors} />
      </div>

      {/* Who We Are */}
      <div id="about">
      <WhoWeAre colors={colors} />
      </div>

      {/* What We Do */}
      <div id="services">
        <WhatWeDo colors={colors} />
      </div>

      {/* Achievements */}
      <div id="achievements">
        <OurAchievements colors={colors} />
      </div>

      {/* Types of Scams - Enhanced with Lusion card styling */}
      <div id="scam-types">
        <ScamTypesSection colors={colors} />
      </div>

      {/* Prevention Tips - Enhanced with gradient backgrounds */}
      <div id="prevention-tips">
        <PreventionTipsSection colors={colors} />
      </div>

      {/* News & Articles Section - Enhanced with Lusion styling */}
      <div id="articles">
      <ArticleCarousel colors={colors} />
      </div>

      {/* Report a Scam Section - Enhanced with Lusion-inspired CTA */}
    <section id="report" className="relative py-24 text-gray-900 overflow-hidden z-10">
      {/* /* Decorative elements (now subtle gray) */} 
        <div className="absolute inset-0 opacity-5">
          <div className="absolute top-0 left-0 w-32 h-32 bg-gray-300 rounded-full mix-blend-overlay transform -translate-x-1/2 -translate-y-1/2"></div>
          <div className="absolute bottom-0 right-0 w-64 h-64 bg-gray-300 rounded-full mix-blend-overlay transform translate-x-1/2 translate-y-1/2"></div>
        </div>

        <div className="max-w-5xl mx-auto px-6 text-center relative">
          <div className="mb-2">
            <span className="inline-block px-4 py-2 bg-gray-100 backdrop-blur-sm rounded-full text-sm font-semibold tracking-wider text-gray-700">
          SCAM ALERT
            </span>
          </div>
          
          <h2 className="text-5xl font-bold mb-6 leading-tight">
            Been <span className="text-blue-600">Scammed</span> or Spotted a Scam?
          </h2>
          
          <p className="text-xl mb-10 text-gray-600 max-w-3xl mx-auto leading-relaxed">
            Your report could protect hundreds of others from falling victim to the same scam. 
            Together we can fight fraud.
          </p>
          
          <div className="flex flex-col sm:flex-row justify-center gap-4">
            <motion.button
          whileHover={{ 
            scale: 1.03,
            boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.1)"
          }}
          whileTap={{ scale: 0.98 }}
          className="px-8 py-4 bg-blue-600 hover:bg-blue-700 text-white rounded-xl font-bold shadow-lg hover:shadow-xl transition-all duration-300 flex items-center justify-center mx-auto sm:mx-0"
          onClick={() => setModalOpen(true)}
            >
          Report a Scam Now
          <FaArrowRight className="ml-3 transition-transform group-hover:translate-x-1" />
            </motion.button>
            
            <motion.button
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.98 }}
          className="px-8 py-4 bg-transparent border-2 border-gray-300 hover:border-gray-400 text-gray-700 rounded-xl font-bold shadow hover:shadow-md transition-all duration-300 flex items-center justify-center mx-auto sm:mx-0"
          onClick={() => window.location.href = '/AllArticlesPage'}
            >
          Learn How to Spot Scams
            </motion.button>
          </div>
          
          <div className="mt-12 flex justify-center">
            <div className="flex items-center text-sm text-gray-500">
          <FaShieldAlt className="mr-2 text-blue-500" />
          <span>All reports are anonymous and confidential</span>
            </div>
          </div>
        </div>
          </section>

        {/* Report Scam Modal */}
      {modalOpen && <ReportScam isOpen={modalOpen} onClose={() => setModalOpen(false)} colors={colors} />}
        
      </div>
      {/* Footer */}
      <Footer/>
    </div>
  );
};

export default Home;