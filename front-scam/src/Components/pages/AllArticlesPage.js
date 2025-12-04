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

// Fallback embedded articles for when API fails
const FALLBACK_ARTICLES = [
  {
    title: "Understanding Phishing Attacks and How to Avoid Them",
    description: "Phishing attacks are one of the most common forms of cybercrime. Learn how to recognize suspicious emails, links, and messages that try to steal your personal information.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1563986768609-322da13575f3?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Investment Scam Warning: Too Good to Be True",
    description: "Learn to identify fraudulent investment schemes promising unrealistic returns. Protect your savings from scammers offering guaranteed high profits with zero risk.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1579621970563-ebec7560ff3e?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Romance Scams: Protecting Your Heart and Wallet",
    description: "Online dating scams are on the rise. Discover the red flags of romance scams and how to protect yourself from emotional and financial exploitation.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Tech Support Scams: Don't Give Remote Access",
    description: "Fake tech support calls and pop-ups are designed to trick you into giving scammers access to your computer. Learn how to identify and avoid these scams.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Identity Theft Prevention: Secure Your Personal Data",
    description: "Your personal information is valuable. Follow these essential steps to protect your identity from thieves and minimize the risk of identity theft.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Cryptocurrency Scams: Stay Safe in the Digital Currency World",
    description: "The cryptocurrency boom has attracted scammers. Learn about common crypto scams including fake exchanges, pump-and-dump schemes, and fraudulent ICOs.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1518546305927-5a555bb7020d?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Social Engineering: The Psychology Behind Scams",
    description: "Scammers use psychological manipulation to trick victims. Understand the tactics of social engineering and how to recognize when you're being manipulated.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Online Shopping Safety: Spot Fake Websites",
    description: "Learn how to identify fraudulent online stores and protect your credit card information when shopping online. Know the signs of legitimate e-commerce sites.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Email Security: Protecting Your Inbox from Scammers",
    description: "Your email is a gateway to your personal information. Learn best practices for email security and how to identify suspicious messages before clicking.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1557200134-90327ee9fafa?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Charity Scams: Verify Before You Donate",
    description: "Fake charities exploit people's generosity. Learn how to verify legitimate charities and avoid donation scams, especially after natural disasters.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1532629345422-7515f3d16bb6?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Work-From-Home Scams: Job Offer Red Flags",
    description: "Remote work opportunities have increased, but so have job scams. Learn to identify fake job postings and employment fraud schemes.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1556761175-4b46a572b786?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Banking Security: Protect Your Financial Accounts",
    description: "Secure your bank accounts from unauthorized access. Learn about multi-factor authentication, secure passwords, and monitoring your accounts for suspicious activity.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1563013544-824ae1b704d3?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Mobile Phone Scams: Text and Call Fraud Prevention",
    description: "Scammers use SMS and phone calls to deceive victims. Learn about smishing, vishing, and other mobile-based scams and how to protect yourself.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Ransomware Protection: Safeguard Your Data",
    description: "Ransomware attacks can lock you out of your own files. Learn how to prevent ransomware infections and what to do if you become a victim.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Lottery and Prize Scams: If It Sounds Too Good...",
    description: "You didn't win a lottery you never entered. Learn how prize scams work and why asking for fees to claim winnings is always a red flag.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1560472355-536de3962603?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Senior Citizens and Scams: Protecting Elderly Loved Ones",
    description: "Seniors are often targeted by scammers. Learn about common scams targeting older adults and how to help protect your elderly family members.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1581579438747-1dc8d17bbce4?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Password Security: Creating Unbreakable Credentials",
    description: "Weak passwords are an open door for hackers. Learn how to create strong, unique passwords and use password managers effectively.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  },
  {
    title: "Tax Season Scams: IRS Impersonation Fraud",
    description: "Scammers impersonate the IRS to steal money and personal information. Learn how to identify fake tax-related communications and protect yourself.",
    url: "#",
    urlToImage: "https://images.unsplash.com/photo-1554224155-6726b3ff858f?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80",
    publishedAt: new Date().toISOString()
  }
];

const AllArticlesPage = () => {
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [usingFallback, setUsingFallback] = useState(false);
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

        // Check if API returned empty results (fallback scenario)
        if (!response.data.articles || response.data.articles.length === 0) {
          console.log("API returned no articles, using fallback");
          setArticles(FALLBACK_ARTICLES);
          setUsingFallback(true);
          setLoading(false);
          return;
        }

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
        console.error("Error fetching scam news, using fallback articles:", err);
        // Use fallback articles when API fails
        setArticles(FALLBACK_ARTICLES);
        setUsingFallback(true);
        setError(null); // Clear error since we have fallback content
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

      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Header Section */}
        <div className="text-center mb-8">
          {usingFallback && (
            <motion.div 
              className="mb-4 inline-block px-4 py-2 bg-yellow-50 border border-yellow-200 rounded-lg text-sm text-yellow-800"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
            </motion.div>
          )}
          <h1 className="text-4xl font-bold text-gray-900 mb-4">Scam Awareness Articles</h1>
          <p className="text-lg text-gray-600">Stay informed and protect yourself from fraud</p>
        </div>

        {/* Search Bar */}
        <div className="mb-8 max-w-xl mx-auto">
          <div className="relative">
            <FaSearch className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Search articles..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1); // Reset to first page on search
              }}
              className="w-full pl-12 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>

        {/* Articles Grid */}
        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
          </div>
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