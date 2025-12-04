import WithAuth from "../hooks/WithAuth";
import React, { useState, useEffect, useMemo } from "react"; // Added useMemo
import axios from "../../utils/axios";
import { motion } from "framer-motion";
import { Table, Input, Select, Button, message, Spin, Progress, Modal, DatePicker } from "antd";
import { FaSort, FaFilter, FaSyncAlt, FaEye } from "react-icons/fa";
import useMediaQuery from "@mui/material/useMediaQuery";
import { Viewer, Worker } from "@react-pdf-viewer/core";
import "@react-pdf-viewer/core/lib/styles/index.css";
import ReactPlayer from "react-player";
import ModalImage from "react-modal-image";
import ReactAudioPlayer from "react-h5-audio-player";
import "react-h5-audio-player/lib/styles.css";
import dayjs from "dayjs";
import WithAuthEx from "../hooks/WithAuthEx";


const { RangePicker } = DatePicker;

const ScamReportsTable = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({
    user_id: "",
    scam_type: "",
    report_status: "",
    scam_date_range: null,
  });
  const [sortedInfo, setSortedInfo] = useState({});
  const [proofModalVisible, setProofModalVisible] = useState(false);
  const [proofData, setProofData] = useState(null);
  const [cancellationReason, setCancellationReason] = useState("");
  const [cancellationModalVisible, setCancellationModalVisible] = useState(false);
  const [currentReport, setCurrentReport] = useState(null);
  const isMobile = useMediaQuery("(max-width: 768px)");
  const [expandedRows, setExpandedRows] = useState({});
  const [modalVisible, setModalVisible] = useState(false);
  const [selectedMessage, setSelectedMessage] = useState("");
  const [pendingStatus, setPendingStatus] = useState("");

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

  // Fetch reports on component mount
  useEffect(() => {
    fetchReports();
  }, []);

  // Fetch reports from the API
  const fetchReports = async () => {
    setLoading(true);
    try {
      const res = await axios.get("/api/scam-reports-modified");
      setReports(res.data);
    } catch (error) {
      console.error("Error fetching reports:", error);
      message.error("Failed to fetch reports. Please try again later.");
    }
    setLoading(false);
  };

  // Open modal to display full description
  const handleOpenModal = (message) => {
    setSelectedMessage(message);
    setModalVisible(true);
  };

  // Handle filter changes
  const handleFilterChange = (key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  // Reset all filters
  const resetFilters = () => {
    setFilters({
      user_id: "",
      scam_type: "",
      report_status: "",
      scam_date_range: null,
    });
  };

  // Update report status
  const updateStatus = async (record, newStatus) => {
    if (newStatus === "Closed" || newStatus === "Resolved") {
      setCurrentReport(record);
      setCancellationModalVisible(true);
      setPendingStatus(newStatus);
    } else {
      try {
        await axios.put(`/external-report-update/${record.report_id}`, {
          report_status: newStatus,
        });
        fetchReports();
        message.success(`Status updated to ${newStatus}.`);
      } catch (error) {
        console.error("Error updating status:", error);
        message.error("Failed to update status. Please try again.");
      }
    }
  };

  // Handle cancellation reason submission
  const handleCancellationSubmit = async () => {
    try {
      await axios.put(`/external-report-update/${currentReport.report_id}`, {
        report_status: pendingStatus,
        admin_comments: cancellationReason,
      });
      setCancellationModalVisible(false);
      setCancellationReason("");
      fetchReports();
      message.success(`Status updated to ${pendingStatus}`);
    } catch (error) {
      console.error("Error updating status:", error);
      message.error("Failed to update status. Please try again.");
    }
  };

  // Handle viewing proof
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

  // Filter data based on applied filters
  const filteredData = useMemo(() => {
    let data = [...reports];

    // Filter by user_id
    if (filters.user_id) {
      data = data.filter((report) =>
        String(report.user_id).includes(filters.user_id)
      );
    }

    // Filter by scam_type
    if (filters.scam_type) {
      data = data.filter((report) => report.scam_type === filters.scam_type);
    }

    // Filter by report_status
    if (filters.report_status) {
      data = data.filter((report) => report.report_status === filters.report_status);
    }

    // Filter by scam_date_range
    if (filters.scam_date_range) {
      const [startDate, endDate] = filters.scam_date_range;
      data = data.filter((report) => {
        const scamDate = dayjs(report.scam_date);
        return scamDate.isAfter(startDate) && scamDate.isBefore(endDate);
      });
    }

    return data;
  }, [reports, filters]);

  // Determine the type of proof (image, PDF, video, audio)
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

  // Table columns definition
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
          <Select.Option value="Waiting for Update">Waiting for Update</Select.Option>
          <Select.Option value="Under Review">Under Review</Select.Option>
          <Select.Option value="Escalated">Escalated</Select.Option>
          <Select.Option value="Resolved">Resolved</Select.Option>
          <Select.Option value="Closed">Closed</Select.Option>
          <Select.Option value="On Hold">On Hold</Select.Option>
        </Select>
      ),
    },
    {
      title: "Scam Date",
      dataIndex: "scam_date",
      key: "scam_date",
      sorter: (a, b) => new Date(a.scam_date) - new Date(b.scam_date),
      render: (text) => dayjs(text).format("YYYY-MM-DD"),
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
      render: (text) => dayjs(text).format("YYYY-MM-DD | HH:mm:ss"),
      responsive: ["md"],
    },
    {
      title: "Description",
      dataIndex: "description",
      key: "description",
      responsive: ["lg"],
      render: (text) => (
        <div>
          {text.length > 10 ? (
            <>
              {text.substring(0, 10)}...
              <Button type="link" icon={<FaEye />} onClick={() => handleOpenModal(text)} />
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
          ""
        ),
    },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      id="Analytics"
      className="bg-white rounded-xl shadow-md overflow-x-auto p-5 mt-4"
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
        {/* User ID Filter */}
        <Input
          placeholder="Search User ID"
          value={filters.user_id}
          onChange={(e) => handleFilterChange("user_id", e.target.value)}
          style={{ width: 150 }}
        />

        {/* Scam Type Filter */}
        <Select
          placeholder="Select Scam Type"
          value={filters.scam_type || null}
          onChange={(value) => handleFilterChange("scam_type", value)}
          style={{ width: 200 }}
          allowClear
        >
          {scamTypes.map((type) => (
            <Select.Option key={type} value={type}>
              {type}
            </Select.Option>
          ))}
        </Select>

        {/* Report Status Filter */}
        <Select
          placeholder="Select Report Status"
          value={filters.report_status || null}
          onChange={(value) => handleFilterChange("report_status", value)}
          style={{ width: 200 }}
          allowClear
        >
          {[
            "In Progress",
            "Waiting for Update",
            "Under Review",
            "Escalated",
            "Resolved",
            "Closed",
            "On Hold",
          ].map((status) => (
            <Select.Option key={status} value={status}>
              {status}
            </Select.Option>
          ))}
        </Select>

        {/* Scam Date Range Filter */}
        <RangePicker
          value={filters.scam_date_range}
          onChange={(dates) => handleFilterChange("scam_date_range", dates)}
          style={{ width: 250 }}
        />

        {/* Reset Filters Button */}
        <Button
          type="primary"
          onClick={resetFilters}
          style={{
            backgroundColor: "#1890ff",
            borderColor: "#1890ff",
          }}
          onMouseEnter={(e) => {
            e.target.style.backgroundColor = "#ff4d4f";
            e.target.style.borderColor = "#ff4d4f";
          }}
          onMouseLeave={(e) => {
            e.target.style.backgroundColor = "#1890ff";
            e.target.style.borderColor = "#1890ff";
          }}
        >
          Reset Filters
        </Button>
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

      {/* Description Modal */}
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
        title="Comments"
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
          placeholder="Enter the reason"
        />
      </Modal>
    </motion.div>
  );
};

export default WithAuthEx(ScamReportsTable);