import React, { useState, useEffect } from "react";
import axios from "../../utils/axios";
import { motion } from "framer-motion";
import { FaArrowRight, FaCalendarAlt, FaSearch, FaShieldAlt } from "react-icons/fa";
import { Helmet } from "react-helmet";
import DynamicBackground from "./component/DynamicBackground";
import Navbar from "./Navbar";
import Profile from "../User/Profile";
import Footer from "../User/Footer";

// Default scam awareness image
const DEFAULT_SCAM_IMAGE = "https://images.unsplash.com/photo-1563986768609-322da13575f3?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=80";

const AllArticlesPage = () => {
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const articlesPerPage = 6; // Reduced for better mobile view

      // Define the missing variables
      const [isMenuOpen, setIsMenuOpen] = useState(false);
    
      // Lusion-inspired color palette
      const colors = {
        primary: "#2563eb",       // Vibrant blue
        secondary: "#1e293b",     // Dark slate
        accent: "#f59e0b",        // Amber
        light: "#f8fafc",         // Lightest slate
        dark: "#0f172a",          // Darkest slate
      };
  
      const navigateToContactUs = () => {
        window.location.href = "/ContactUs"; // Adjust the path as per your routing setup
      };
  // Strict scam-related keywords
  const scamKeywords = [
    "scam", "fraud", "phishing", "identity theft", 
    "online scam", "financial fraud", "cybercrime",
    "investment scam", "romance scam", "tech support scam"
  ];

  useEffect(() => {
    const fetchScamArticles = async () => {
      try {
        // Call backend API instead of directly calling News API
        const response = await axios.get('/api/news', {
          params: {
            q: 'scam awareness OR fraud prevention',
            pageSize: 30,
            sortBy: 'publishedAt',
            language: 'en'
          }
        });

        // Filter for scam-specific content and add default image if missing
        const filteredArticles = response.data.articles
          .filter(article => 
            scamKeywords.some(keyword => 
              article.title?.toLowerCase().includes(keyword) ||
              article.description?.toLowerCase().includes(keyword)
            )
          )
          .map(article => ({
            ...article,
            urlToImage: article.urlToImage || DEFAULT_SCAM_IMAGE
          }));

        setArticles(filteredArticles);
      } catch (err) {
        console.error("Error fetching scam news:", err);
        setError("Failed to load scam awareness articles. Please try again later.");
      } finally {
        setLoading(false);
      }
    };

    fetchScamArticles();
  }, []);

  // Filter articles based on search term
  const filteredArticles = articles.filter((article) => {
    return (
      article.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      article.description?.toLowerCase().includes(searchTerm.toLowerCase())
    );
  });

  // Pagination logic
  const indexOfLastArticle = currentPage * articlesPerPage;
  const indexOfFirstArticle = indexOfLastArticle - articlesPerPage;
  const currentArticles = filteredArticles.slice(indexOfFirstArticle, indexOfLastArticle);
  const totalPages = Math.ceil(filteredArticles.length / articlesPerPage);

  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  // Format date
  const formatDate = (dateString) => {
    const options = { year: "numeric", month: "short", day: "numeric" };
    return new Date(dateString).toLocaleDateString(undefined, options);
  };

  return (
    <div className="min-h-screen bg-gray-50">
        <div>
            <DynamicBackground/>
        </div>
              {/* Modern Navbar with Lusion-inspired styling */}
      <Navbar colors={colors} isMenuOpen={isMenuOpen} setIsMenuOpen={setIsMenuOpen} />
      
      {/* Profile positioned absolutely */}
      <div className="absolute top-6 right-6 z-50">
        <Profile colors={colors} />
      </div>
      <Helmet>
        <title>Scam Awareness News | Protect Yourself From Fraud</title>
      </Helmet>

      <div className="max-w-7xl mx-auto">
        {/* Header and Search (unchanged) */}

        {/* Articles Grid */}
        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
          </div>
        ) : error ? (
          <div className="text-center py-12 text-red-500">{error}</div>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {currentArticles.map((article, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                  whileHover={{ y: -5 }}
                  className="bg-white rounded-lg shadow-md overflow-hidden hover:shadow-lg transition-all duration-300 flex flex-col h-full"
                >
                  <div className="relative h-48 overflow-hidden">
                    <img
                      src={article.urlToImage}
                      alt={article.title}
                      className="w-full h-full object-cover"
                      onError={(e) => {
                        e.target.src = DEFAULT_SCAM_IMAGE;
                      }}
                    />
                    <div className="absolute inset-0 bg-gradient-to-t from-black/50 to-transparent"></div>
                  </div>
                  <div className="p-6 flex-grow">
                    <div className="flex items-center mb-2">
                      <span className="text-xs font-medium text-blue-600">
                        {formatDate(article.publishedAt)}
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-gray-900 mb-2 line-clamp-2">
                      {article.title}
                    </h3>
                    <p className="text-gray-600 text-sm mb-4 line-clamp-3">
                      {article.description}
                    </p>
                  </div>
                  <div className="px-6 pb-4">
                    <a
                      href={article.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center text-blue-500 text-sm font-medium hover:text-blue-600"
                    >
                      Read Safety Tips <FaArrowRight className="ml-1" />
                    </a>
                  </div>
                </motion.div>
              ))}
            </div>

            {/* Enhanced Pagination */}
            {filteredArticles.length > articlesPerPage && (
              <div className="flex flex-col sm:flex-row items-center justify-between mt-8 gap-4">
                <div className="text-sm text-gray-500">
                  Showing {indexOfFirstArticle + 1}-{Math.min(indexOfLastArticle, filteredArticles.length)} of {filteredArticles.length} articles
                </div>
                
                <div className="flex gap-1">
                  <button
                    onClick={() => paginate(currentPage - 1)}
                    disabled={currentPage === 1}
                    className="px-4 py-2 rounded-md border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                  >
                    Previous
                  </button>
                  
                  {Array.from({ length: Math.min(5, totalPages) }).map((_, idx) => {
                    // Show limited page numbers with ellipsis
                    let pageNum;
                    if (totalPages <= 5) {
                      pageNum = idx + 1;
                    } else if (currentPage <= 3) {
                      pageNum = idx + 1;
                    } else if (currentPage >= totalPages - 2) {
                      pageNum = totalPages - 4 + idx;
                    } else {
                      pageNum = currentPage - 2 + idx;
                    }

                    return (
                      <button
                        key={idx}
                        onClick={() => paginate(pageNum)}
                        className={`px-4 py-2 rounded-md border ${
                          currentPage === pageNum
                            ? "border-blue-500 bg-blue-50 text-blue-600"
                            : "border-gray-300 text-gray-700 hover:bg-gray-50"
                        }`}
                      >
                        {pageNum}
                      </button>
                    );
                  })}

                  {totalPages > 5 && (
                    <span className="px-2 py-2">...</span>
                  )}

                  <button
                    onClick={() => paginate(currentPage + 1)}
                    disabled={currentPage === totalPages}
                    className="px-4 py-2 rounded-md border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default AllArticlesPage;