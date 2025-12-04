import React, { useState, useEffect } from "react";
import axios from "../../utils/axios";
import { FiChevronRight, FiCheck, FiClock, FiX, FiAlertCircle } from "react-icons/fi";

const ReportHistory = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        setLoading(true);

        // Fetch reports for the logged-in user (JWT automatically included)
        const response = await axios.get("/api/reports");
        setReports(response.data);
      } catch (err) {
        console.error("Error fetching reports:", err);
        setError(err.message || "Failed to fetch reports.");
      } finally {
        setLoading(false);
      }
    };

    fetchReports();
  }, []);

  const getStatusIcon = (status) => {
    switch (status) {
      case "Submitted":
        return <FiClock className="text-blue-500" />;
      case "Under Review":
        return <FiAlertCircle className="text-yellow-500" />;
      case "In Progress":
        return <FiAlertCircle className="text-orange-500" />;
      case "Resolved":
        return <FiCheck className="text-green-500" />;
      case "Closed":
        return <FiCheck className="text-green-500" />;
      case "Cancelled":
        return <FiX className="text-red-500" />;
      case "Waiting for Update":
        return <FiClock className="text-purple-500" />;
      default:
        return <FiClock className="text-gray-500" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "Submitted":
        return "bg-blue-100 text-blue-800";
      case "Under Review":
        return "bg-yellow-100 text-yellow-800";
      case "In Progress":
        return "bg-orange-100 text-orange-800";
      case "Resolved":
        return "bg-green-100 text-green-800";
      case "Closed":
        return "bg-green-100 text-green-800";
      case "Cancelled":
        return "bg-red-100 text-red-800";
      case "Waiting for Update":
        return "bg-purple-100 text-purple-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-2xl font-bold text-gray-900 mb-8">My Scam Reports</h1>

        {loading ? (
          <div className="flex justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
          </div>
        ) : error ? (
          <div className="text-center py-12">
            <p className="text-red-500">{error}</p>
          </div>
        ) : reports.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-gray-500">No scam reports found</p>
          </div>
        ) : (
          <div className="space-y-6">
            {reports.map((report) => (
              <div key={report.report_id} className="bg-white shadow rounded-lg overflow-hidden">
                <div className="p-4 sm:p-6">
                  <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start">
                    <div className="mb-4 sm:mb-0">
                      <h2 className="text-lg font-semibold text-gray-900">
                        Report #{report.report_id}
                      </h2>
                      <p className="text-sm text-gray-500">
                        {new Date(report.submitted_at).toLocaleDateString("en-US", {
                          year: "numeric",
                          month: "long",
                          day: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </p>
                    </div>
                    <span
                      className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(
                        report.report_status
                      )}`}
                    >
                      {getStatusIcon(report.report_status)}
                      <span className="ml-1">{report.report_status}</span>
                    </span>
                  </div>

                  <div className="mt-4">
                    <h3 className="text-sm font-medium text-gray-900">Scam Type</h3>
                    <p className="mt-1 text-sm text-gray-600 capitalize">
                      {report.scam_type.toLowerCase()}
                    </p>
                  </div>

                  <div className="mt-4">
                    <h3 className="text-sm font-medium text-gray-900">Description</h3>
                    <p className="mt-1 text-sm text-gray-600">
                      {report.description || "No description provided"}
                    </p>
                  </div>

                  {report.admin_comments && (
                    <div className="mt-4">
                      <h3 className="text-sm font-medium text-gray-900">Admin Comments</h3>
                      <p className="mt-1 text-sm text-gray-600">{report.admin_comments}</p>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ReportHistory;