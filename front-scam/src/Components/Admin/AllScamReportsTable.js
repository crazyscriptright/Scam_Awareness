import React, { useState, useEffect, useMemo } from "react";
import axios from "../../utils/axios";
import { Table, Input, Select, Button, Spin, DatePicker, message, Modal } from "antd";
import { FaSyncAlt } from "react-icons/fa";
import dayjs from "dayjs";
import { motion } from "framer-motion";
import { FaEye, } from "react-icons/fa";
import WithAuth from "../hooks/WithAuth";




const { RangePicker } = DatePicker;

const AllScamReportsTable = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({
    user_id: "",
    scam_type: "",
    report_status: "",
    scam_date_range: null,
  });
  const [descriptionModalVisible, setDescriptionModalVisible] = useState(false);
  const [selectedDescription, setSelectedDescription] = useState("");

  // Fetch all reports (without proof)
  const fetchReports = async () => {
    setLoading(true);
    try {
      const res = await axios.get("/api/all-scam-reports");
      if (res.data) {
        setReports(res.data);
      } else {
        message.error("No data received from the server.");
      }
    } catch (error) {
      console.error("Error fetching reports:", error);
      message.error("Failed to fetch reports. Please try again later.");
    } finally {
      setLoading(false);
    }
  };

  // Fetch data on component mount
  useEffect(() => {
    fetchReports();
  }, []);

  // Apply filters and sorting to the data
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

  // Handle "Read More" for description
  const handleReadMore = (description) => {
    setSelectedDescription(description);
    setDescriptionModalVisible(true);
  };

  // Columns definition
  const columns = [
    {
      title: "Report ID",
      dataIndex: "report_id",
      key: "report_id",
      sorter: (a, b) => a.report_id - b.report_id,
    },
    {
      title: "User ID",
      dataIndex: "user_id",
      key: "user_id",
      sorter: (a, b) => a.user_id - b.user_id,
    },
    {
      title: "Scam Type",
      dataIndex: "scam_type",
      key: "scam_type",
      sorter: (a, b) => a.scam_type.localeCompare(b.scam_type),
    },
    {
      title: "Scam Date",
      dataIndex: "scam_date",
      key: "scam_date",
      sorter: (a, b) => new Date(a.scam_date) - new Date(b.scam_date),
      render: (text) => dayjs(text).format("YYYY-MM-DD"), // Format to date only
    },
    {
      title: "Status",
      dataIndex: "report_status",
      key: "report_status",
      sorter: (a, b) => a.report_status.localeCompare(b.report_status),
    },
    {
      title: "Last Modified",
      dataIndex: "last_modified",
      key: "last_modified",
      sorter: (a, b) => new Date(a.last_modified) - new Date(b.last_modified),
      render: (text) => dayjs(text).format("YYYY-MM-DD | HH:mm:ss"), // Format to date and time
    },
    {
      title: "Description",
      dataIndex: "description",
      key: "description",
      render: (text) => (
        <div>
          {text.length > 15 ? `${text.substring(0, 15)}...` : text}
          {text.length > 15 && (
            <Button type="link" icon={<FaEye />} onClick={() => handleReadMore(text)}>
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      <div className="pb-5">  </div>
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="p-4 md:p-6 bg-white rounded-xl shadow-md overflow-x-auto pb-4 mt-4"
      >
        {/* Header */}
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg md:text-2xl font-bold">All Scam Reports</h2>
          <Button type="primary" icon={<FaSyncAlt />} onClick={fetchReports} loading={loading}>
            Refresh
          </Button>
        </div>

        {/* Filters */}
        <motion.div
          className="flex flex-wrap gap-4 mb-4"
          initial={{ opacity: 0, y: -20 }} // Initial animation state
          animate={{ opacity: 1, y: 0 }} // Animate to this state
          transition={{ duration: 0.5 }} // Animation duration
        >
          {/* User ID Filter */}
          <motion.div
            whileHover={{ scale: 1.05 }} // Hover effect
            whileTap={{ scale: 0.95 }} // Click effect
          >
            <Input
              placeholder="Search User ID"
              value={filters.user_id}
              onChange={(e) => setFilters((prev) => ({ ...prev, user_id: e.target.value }))}
              style={{ width: 150 }}
            />
          </motion.div>

          {/* Scam Type Filter */}
          <motion.div
            whileHover={{ scale: 1.05 }} // Hover effect
            whileTap={{ scale: 0.95 }} // Click effect
          >
            <Select
              placeholder="Select Scam Type"
              value={filters.scam_type || null}
              onChange={(value) => setFilters((prev) => ({ ...prev, scam_type: value }))}
              style={{ width: 200 }}
              allowClear
            >
              {[
                "Investment",
                "Romance scams",
                "Product and service scams",
                "Threats and extortion scams",
                "Jobs and employment scams",
                "Unexpected money",
                "Phishing",
                "Buying or selling scams",
                "Other",
              ].map((type) => (
                <Select.Option key={type} value={type}>
                  {type}
                </Select.Option>
              ))}
            </Select>
          </motion.div>

          {/* Report Status Filter */}
          <motion.div
            whileHover={{ scale: 1.05 }} // Hover effect
            whileTap={{ scale: 0.95 }} // Click effect
          >
            <Select
              placeholder="Select Report Status"
              value={filters.report_status || null}
              onChange={(value) => setFilters((prev) => ({ ...prev, report_status: value }))}
              style={{ width: 200 }}
              allowClear
            >
              {[
                "Submitted",
                "Pending",
                "In Progress",
                "Waiting for Update",
                "Under Review",
                "Escalated",
                "Resolved",
                "Closed",
                "On Hold",
                "Cancelled",
              ].map((status) => (
                <Select.Option key={status} value={status}>
                  {status}
                </Select.Option>
              ))}
            </Select>
          </motion.div>

          {/* Scam Date Range Filter */}
          <motion.div
            whileHover={{ scale: 1.05 }} // Hover effect
            whileTap={{ scale: 0.95 }} // Click effect
          >
            <RangePicker
              value={filters.scam_date_range}
              onChange={(dates) => setFilters((prev) => ({ ...prev, scam_date_range: dates }))}
              style={{ width: 250 }}
            />
          </motion.div>

          {/* Reset Filters Button */}
          <motion.div
            whileHover={{ scale: 1.05 }} // Hover effect
            whileTap={{ scale: 0.95 }} // Click effect
          >
            <Button
              type="primary" // Blue background by default
              style={{
                backgroundColor: "#1890ff", // Blue background
                borderColor: "#1890ff", // Blue border
              }}
              onMouseEnter={(e) => {
                e.target.style.backgroundColor = "#ff4d4f"; // Red background on hover
                e.target.style.borderColor = "#ff4d4f"; // Red border on hover
              }}
              onMouseLeave={(e) => {
                e.target.style.backgroundColor = "#1890ff"; // Revert to blue background
                e.target.style.borderColor = "#1890ff"; // Revert to blue border
              }}
              onClick={() =>
                setFilters({
                  user_id: "",
                  scam_type: "",
                  report_status: "",
                  scam_date_range: null,
                })
              }
            >
              Reset Filters
            </Button>
          </motion.div>
        </motion.div>

        {/* Table */}
        {loading ? (
          <div className="flex flex-col items-center">
            <Spin tip="Loading reports..." />
          </div>
        ) : (
          <Table
            columns={columns}
            dataSource={filteredData}
            rowKey="report_id"
            pagination={{ pageSize: 5 }} // 5 rows per page
            scroll={{ x: "max-content" }}
          />
        )}

        {/* Description Modal */}
        <Modal
          title="Description"
          visible={descriptionModalVisible}
          onCancel={() => setDescriptionModalVisible(false)}
          footer={null}
        >
          <p>{selectedDescription}</p>
        </Modal>
      </motion.div>
    </div>
  );
};

export default WithAuth(AllScamReportsTable);