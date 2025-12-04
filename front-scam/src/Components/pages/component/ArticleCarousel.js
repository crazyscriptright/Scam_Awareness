import { Swiper, SwiperSlide } from 'swiper/react';
import { Pagination, Autoplay } from 'swiper/modules';
import { FaArrowRight, FaCalendarAlt, FaClock } from 'react-icons/fa';
import { motion } from 'framer-motion';
import { Helmet } from "react-helmet";
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from '../../../utils/axios';

// Import Swiper styles
import 'swiper/css';
import 'swiper/css/pagination';

const ArticleCarousel = () => {
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchNews = async () => {
      try {
        // Search for scam-related terms with higher priority
        const scamTerms = [
            "scam", "fraud", "phishing", "identity theft", 
            "online scam", "financial fraud", "cybercrime",
            "investment scam", "romance scam", "tech support scam"
        ].join(' OR ');
        
        // Call backend API instead of directly calling News API
        const response = await axios.get('/api/news', {
          params: {
            q: scamTerms,
            pageSize: 20,
            language: 'en',
            sortBy: 'publishedAt'
          }
        });
        
        const data = response.data;
        
        // Filter articles with images and required fields, and further filter for scam-related content
        const filteredArticles = data.articles
          .filter(article => 
            article.urlToImage && 
            article.title && 
            article.description &&
            // Additional content filtering
            (
              article.title.toLowerCase().includes('scam') ||
              article.title.toLowerCase().includes('phishing') ||
              article.title.toLowerCase().includes('fraud') ||
              article.description.toLowerCase().includes('scam') ||
              article.description.toLowerCase().includes('phishing') ||
              article.description.toLowerCase().includes('fraud')
            )
          )
          .slice(0, 10) // Take first 10 relevant articles
          .map((article, index) => {
            // Determine category based on content
            let category = "CYBER SECURITY";
            const title = article.title.toLowerCase();
            const desc = article.description.toLowerCase();
            
            if (title.includes('phishing') || desc.includes('phishing')) {
              category = "PHISHING";
            } else if (title.includes('investment') || desc.includes('investment')) {
              category = "INVESTMENT SCAM";
            } else if (title.includes('romance') || desc.includes('romance')) {
              category = "ROMANCE SCAM";
            } else if (title.includes('tech support') || desc.includes('tech support')) {
              category = "TECH SUPPORT SCAM";
            } else if (title.includes('identity') || desc.includes('identity')) {
              category = "IDENTITY THEFT";
            }
            
            return {
              id: index + 1,
              title: article.title,
              category: category,
              excerpt: article.description,
              date: new Date(article.publishedAt).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'long',
                day: 'numeric'
              }),
              readTime: `${Math.max(3, Math.floor(article.content?.length / 1000) || 5)} min read`,
              image: article.urlToImage,
              link: article.url
            };
          });
        
        // If we don't have enough scam-specific articles, supplement with general cybersecurity news
        if (filteredArticles.length < 10) {
          const backupResponse = await axios.get('/api/news', {
            params: {
              q: 'cybersecurity',
              pageSize: 10 - filteredArticles.length,
              language: 'en',
              sortBy: 'publishedAt'
            }
          });
          
          if (backupResponse.data) {
            const backupData = backupResponse.data;
            const backupArticles = backupData.articles
              .filter(article => article.urlToImage && article.title && article.description)
              .slice(0, 10 - filteredArticles.length)
              .map((article, index) => ({
                id: filteredArticles.length + index + 1,
                title: article.title,
                category: "CYBER SECURITY",
                excerpt: article.description,
                date: new Date(article.publishedAt).toLocaleDateString('en-US', {
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric'
                }),
                readTime: `${Math.max(3, Math.floor(article.content?.length / 1000) || 5)} min read`,
                image: article.urlToImage,
                link: article.url
              }));
            
            setArticles([...filteredArticles, ...backupArticles]);
          } else {
            setArticles(filteredArticles);
          }
        } else {
          setArticles(filteredArticles);
        }
      } catch (err) {
        setError(err.message);
        console.error("Error fetching news:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchNews();
  }, []);

  const categoryColors = {
    "CYBER SECURITY": "bg-blue-500",
    "PHISHING": "bg-purple-500",
    "INVESTMENT SCAM": "bg-red-500",
    "ROMANCE SCAM": "bg-pink-500",
    "TECH SUPPORT SCAM": "bg-orange-500",
    "IDENTITY THEFT": "bg-green-500",
    "FRAUD": "bg-yellow-500",
    "SOCIAL ENGINEERING": "bg-gray-500"
  };

  const handleViewAllArticles = (e) => {
    e.preventDefault();
    navigate("/AllArticlesPage");
  };

  if (loading) {
    return (
      <div className="py-20 bg-white text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
        <p className="mt-4 text-gray-600">Loading scam awareness articles...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="py-20 bg-white text-center">
        <p className="text-red-500">Error: {error}</p>
        <p className="text-gray-600 mt-2">Failed to load scam awareness articles.</p>
      </div>
    );
  }

  if (articles.length === 0) {
    return (
      <div className="py-20 bg-white text-center">
        <p className="text-gray-600">No scam awareness articles available at the moment.</p>
      </div>
    );
  }

  return (
    <div>
      <Helmet>
        <title>Scam Awareness News & Articles | Cybersecurity Resources</title>
        <meta name="description" content="Browse the latest scam awareness news, articles, and prevention guides to protect yourself from online fraud" />
      </Helmet>

      <section className="py-20 relative overflow-hidden">
        {/* Background elements */}
        <div className="absolute inset-0 -z-10">
          <div className="absolute top-0 left-0 w-1/9 h-full bg-gradient-to-r from-white to-transparent z-10"></div>
          <div className="absolute top-0 right-0 w-1/9 h-full bg-gradient-to-l from-white to-transparent z-10"></div>
        </div>

        <div className="max-w-7xl mx-auto px-6">
          <motion.div 
            className="text-center mb-16"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
          >
            <motion.span 
              className="inline-block text-sm font-medium text-blue-500 tracking-widest mb-2 px-4 py-1 bg-blue-50 rounded-full"
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              viewport={{ once: true }}
            >
              SCAM ALERTS
            </motion.span>
            <motion.h2 
              className="text-4xl font-bold text-gray-900 mb-4"
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              viewport={{ once: true }}
            >
              Scam Awareness <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-purple-500">Resources</span>
            </motion.h2>
            <motion.p 
              className="text-lg text-gray-600 max-w-3xl mx-auto"
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.4 }}
              viewport={{ once: true }}
            >
              Stay protected with the latest scam alerts and fraud prevention tips.
            </motion.p>
          </motion.div>

          <Swiper
            modules={[Pagination, Autoplay]}
            spaceBetween={30}
            slidesPerView={1}
            pagination={{ clickable: true }}
            autoplay={{
              delay: 5000,
              disableOnInteraction: false,
            }}
            breakpoints={{
              640: {
                slidesPerView: 1,
                spaceBetween: 20,
              },
              768: {
                slidesPerView: 2,
                spaceBetween: 30,
              },
              1024: {
                slidesPerView: 3,
                spaceBetween: 30,
              },
            }}
            className="pb-12"
          >
            {articles.map((article) => (
              <SwiperSlide key={article.id}>
                <motion.div 
                  whileHover={{ y: -8 }}
                  className="group relative overflow-hidden rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 bg-white h-full"
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5 }}
                  viewport={{ once: true }}
                >
                  <div className="relative overflow-hidden h-60">
                    <img 
                      src={article.image} 
                      alt={article.title} 
                      className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-110" 
                      onError={(e) => {
                        e.target.onerror = null; 
                        e.target.src = 'https://via.placeholder.com/400x200?text=Scam+Awareness';
                      }}
                    />
                    <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/30 to-transparent"></div>
                    <span className={`absolute top-4 left-4 px-3 py-1 text-xs font-medium text-white rounded-full ${categoryColors[article.category] || 'bg-blue-500'}`}>
                      {article.category}
                    </span>
                  </div>
                  <div className="p-6">
                    <h3 className="text-xl font-bold text-gray-900 mb-3 line-clamp-2">{article.title}</h3>
                    <p className="text-gray-600 mb-4 line-clamp-3">{article.excerpt}</p>
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
                      <div className="flex items-center text-sm text-gray-500">
                        <FaCalendarAlt className="mr-2" />
                        <span>{article.date}</span>
                      </div>
                      <div className="flex items-center text-sm text-gray-500">
                        <FaClock className="mr-2" />
                        <span>{article.readTime}</span>
                      </div>
                    </div>
                    <a 
                      href={article.link} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="inline-flex items-center text-blue-500 font-medium group-hover:text-blue-600 transition-colors"
                    >
                      Read Article
                      <FaArrowRight className="ml-2 transition-transform group-hover:translate-x-1" />
                    </a>
                  </div>
                  <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 to-purple-500 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                </motion.div>
              </SwiperSlide>
            ))}
          </Swiper>

          <motion.div 
            className="text-center mt-12"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.4 }}
            viewport={{ once: true }}
          >
            <div className="inline-block">
              <button 
                onClick={handleViewAllArticles}
                className="relative px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-500 text-white font-medium rounded-full hover:shadow-lg transition-all duration-300 hover:from-blue-600 hover:to-purple-600 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-opacity-50"
              >
                View All Scam Alerts
                <span className="absolute inset-0 rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-300 bg-gradient-to-r from-blue-600 to-purple-600 -z-10"></span>
              </button>
            </div>
          </motion.div>

        </div>
      </section>
    </div>
  );
};

export default ArticleCarousel;