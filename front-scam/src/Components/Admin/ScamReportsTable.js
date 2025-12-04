import WithAuth from "../hooks/WithAuth";
import React, { useState, useEffect } from "react";
import axios from "../../utils/axios";
import { motion } from "framer-motion";
import { Table, Input, Select, Button, message, Spin, Progress, Modal } from "antd";
import { FaSort, FaFilter, FaSyncAlt, FaEye } from "react-icons/fa";
import useMediaQuery from "@mui/material/useMediaQuery";
import { Viewer, Worker } from "@react-pdf-viewer/core";
import "@react-pdf-viewer/core/lib/styles/index.css";
import ReactPlayer from "react-player";
import ModalImage from "react-modal-image";
import ReactAudioPlayer from "react-h5-audio-player";
import "react-h5-audio-player/lib/styles.css";
import dayjs from "dayjs";

const ScamReportsTable = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({ scamType: "", reportStatus: "" });
  const [sortedInfo, setSortedInfo] = useState({});
  const [proofModalVisible, setProofModalVisible] = useState(false);
  const [proofData, setProofData] = useState(null);
  const [cancellationReason, setCancellationReason] = useState("");
  const [cancellationModalVisible, setCancellationModalVisible] = useState(false);
  const [currentReport, setCurrentReport] = useState(null);
  const isMobile = useMediaQuery("(max-width: 768px)");
  const [expandedRows, setExpandedRows] = useState({});
  const [modalVisible, setModalVisible] =useState(false);
  const [selectedMessage, setSelectedMessage] =useState(false);

  const toggleExpand = (reportId) => {
    setExpandedRows((prev) => ({
      ...prev,
      [reportId]: !prev[reportId],
    }));
  };

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

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    setLoading(true);
    try {
      const res = await axios.get("/api/scam-reports");
      setReports(res.data);
    } catch (error) {
      console.error("Error fetching reports:", error);
      message.error("Failed to fetch reports. Please try again later.");
    }
    setLoading(false);
  };
  const handleOpenModal = (message) => {
    setSelectedMessage(message);
    setModalVisible(true);
  };

  const handleFilterChange = (key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const resetFilters = () => {
    setFilters({ scamType: "", reportStatus: "" });
  };

  const updateStatus = async (record, newStatus) => {
    if (newStatus === "Cancelled") {
      setCurrentReport(record);
      setCancellationModalVisible(true);
    } else {
      try {
        // Step 1: Update the status in the admin_approval table
        await axios.put(`/admin-approval/${record.report_id}`, {
          report_status: newStatus,
        });

  
        // Fetch the updated reports
        fetchReports();
  
        // Success message
        message.success(`Status updated to ${newStatus}.`);
      } catch (error) {
        console.error("Error updating status ", error);
        message.error("Failed to update status. Please try again.");
      }
    }
  };

  const handleCancellationSubmit = async () => {
    try {
      await axios.put(`/admin-approval/${currentReport.report_id}`, {
        report_status: "Cancelled",
        admin_comments: cancellationReason,
      });
      setCancellationModalVisible(false);
      setCancellationReason("");
      fetchReports();
      message.success("Status updated to Cancelled"); // Success message
    } catch (error) {
      console.error("Error updating status:", error);
      message.error("Failed to update status. Please try again.");
    }
  };

  const handleViewProof = async (reportId) => {
    try {
      const res = await axios.get(`/api/scam-reports/${reportId}/proof`);
      setProofData(res.data);
      setProofModalVisible(true);
    } catch (error) {
      console.error("Error fetching proof:", error);
      message.error("Failed to fetch proof. Please try again later.");
    }
  };


  const filteredData = reports.filter(
    (report) =>
      (!filters.scamType || report.scam_type.toLowerCase().includes(filters.scamType.toLowerCase())) &&
      (!filters.reportStatus || report.report_status === filters.reportStatus)
  );

  const columns = [
    {
      title: "Report ID",
      dataIndex: "report_id",
      key: "report_id",
      sorter: (a, b) => b.report_id - a.report_id,
      defaultSortOrder: "ascend",
    },
    {
      title: "Scam Type",
      dataIndex: "scam_type",
      key: "scam_type",
    },
    {
      title: "Status",
      dataIndex: "report_status",
      key: "report_status",
      render: (text, record) => (
        <Select defaultValue={text} onChange={(value) => updateStatus(record, value)}>
          <Select.Option value="Submitted">Submitted</Select.Option>
          <Select.Option value="In Progress">In Progress</Select.Option>
          <Select.Option value="Cancelled">Cancelled</Select.Option>
        </Select>
      ),
    },
    {
      title: "Scam Date",
      dataIndex: "scam_date",
      key: "scam_date",
      sorter: (a, b) => new Date(a.scam_date) - new Date(b.scam_date),
      render: (text) => dayjs(text).format("YYYY-MM-DD"), // Format to date only
    },
    {
      title: "User ID",
      dataIndex: "user_id",
      key: "user_id",
      responsive: ["md"],
    },
    {
    title: "Submitted At",
    dataIndex: "submitted_at",
    key: "submitted_at",
    sorter: (a, b) => new Date(a.submitted_at) - new Date(b.submitted_at),
    render: (text) => dayjs(text).format("YYYY-MM-DD | HH:mm:ss"), // Format to date and time
    responsive: ["md"],
  },
    {
      title: "Description",
      dataIndex: "description",
      key: "description",
      responsive: ["lg"],
      render: (text) => (
        <div>
          {text.length >10 ? (
            <>
            {text.substring(0,10)}...
            <Button type="link" icon={<FaEye/>} onClick={() => handleOpenModal(text)} />
            </>
          ) : (
            text
          )}
          </div>
      ),
    },
      
    {
      title: "Proof",
      key: "proof",
      render: (_, record) => 
        record.proof ? (
          <Button
            type="link"
            icon={<FaEye />}
            onClick={() => handleViewProof(record.report_id)}
          >
            View
          </Button>
        ) : (
          "" // Returns blank if proof is null
        ),
    },
  ];
    
  const getProofType = (proofData) => {
    if (typeof proofData === "string") {
      if (proofData.startsWith("data:image")) {
        return "image";
      } else if (proofData.startsWith("data:application/pdf")) {
        return "pdf";
      } else if (proofData.startsWith("data:video")) {
        return "video";
      } else if (proofData.startsWith("data:audio")) {
        return "audio";
      }
    }
    return "unknown";
  };

  const proofType = getProofType(proofData);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      id="Analytics"
      className="bg-white rounded-xl shadow-md overflow-x-auto p-5 mt-8"
    >
      {/* Header */}
      <div className="flex flex-wrap justify-between items-center mb-4">
        <h2 className="text-lg md:text-2xl font-bold ">Scam Reports</h2>
        <Button type="primary" icon={<FaSyncAlt />} onClick={fetchReports} loading={loading}>
          Refresh
        </Button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2 md:gap-4 mb-4">
        <motion.select
          value={filters.scamType}
          onChange={(e) => handleFilterChange("scamType", e.target.value)}
          className="w-full md:w-auto p-2 border border-gray-300 rounded-lg bg-white shadow-md transition duration-200 hover:border-blue-500 focus:border-blue-500 focus:outline-none"
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          whileHover={{ scale: 1.05 }}
        >
          <option value="">Filter by scam type</option>
          {scamTypes.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </motion.select>
        <motion.button
          onClick={resetFilters}
          className="px-4 py-2 bg-blue-500 text-white rounded-lg shadow-md transition duration-200 hover:bg-red-600 focus:outline-none"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          Reset Filters
        </motion.button>
      </div>

      {/* Table */}
      {loading ? (
        <div className="flex flex-col items-center">
          <Spin tip="Loading reports..." />
          <Progress percent={100} showInfo={false} style={{ width: "100%", marginTop: 16 }} />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <Table
            columns={columns}
            dataSource={filteredData}
            rowKey="report_id"
            pagination={{ pageSize: 5 }}
            loading={loading}
            onChange={(pagination, filters, sorter) => setSortedInfo(sorter)}
            scroll={{ x: "max-content" }}
          />
        </div>
      )}
      {/* {/* Description Modal} */}
      <Modal
        title="Full Message"
        visible={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={null}
        >
          <p>{selectedMessage}</p>
        </Modal>
      {/* Proof Modal */}
      <Modal
        title="Proof"
        visible={proofModalVisible}
        onCancel={() => setProofModalVisible(false)}
        footer={null}
        width={800}
      >
        {proofData && (
          <div>
            {proofType === "image" ? (
              <ModalImage
                small={proofData}
                large={proofData}
                alt="Proof"
                hideDownload={true}
              />
            ) : proofType === "pdf" ? (
              <Worker workerUrl="https://unpkg.com/pdfjs-dist@3.4.120/build/pdf.worker.min.js">
                <Viewer fileUrl={proofData} />
              </Worker>
            ) : proofType === "video" ? (
              <ReactPlayer url={proofData} controls width="100%" />
            ) : proofType === "audio" ? (
              <ReactAudioPlayer src={proofData} autoPlay={false} />
            ) : (
              <a href={proofData} download="proof">
                Download Proof
              </a>
            )}
          </div>
        )}
      </Modal>

      {/* Cancellation Reason Modal */}
      <Modal
        title="Cancellation Reason"
        visible={cancellationModalVisible}
        onCancel={() => setCancellationModalVisible(false)}
        footer={[
          <Button key="back" onClick={() => setCancellationModalVisible(false)}>
            Cancel
          </Button>,
          <Button key="submit" type="primary" onClick={handleCancellationSubmit}>
            Submit
          </Button>,
        ]}
      >
        <Input.TextArea
          rows={4}
          value={cancellationReason}
          onChange={(e) => setCancellationReason(e.target.value)}
          placeholder="Enter the reason for cancellation"
        />
      </Modal>
    </motion.div>
  );
};

export default WithAuth(ScamReportsTable);