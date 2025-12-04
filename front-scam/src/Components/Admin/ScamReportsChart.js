import WithAuth from "../hooks/WithAuth";
import React, { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, PieChart, Pie, Cell, Legend } from "recharts";
import axios from "../../utils/axios";
import { motion } from "framer-motion";
import { FiBarChart2 } from "react-icons/fi";

const COLORS = ["#0088FE", "#00C49F", "#FFBB28", "#FF8042", "#A28EFF", "#FF6384", "#36A2EB", "#4BC0C0", "#FF9F40"];

const ScamReportsChart = () => {
  const [reportStatusData, setReportStatusData] = useState([]);
  const [scamTypeData, setScamTypeData] = useState([]);

  useEffect(() => {
    axios.get("/api/users/scam-reports")
      .then((res) => {
        processChartData(res.data);
      })
      .catch((err) => console.error("Error fetching scam reports", err));
  }, []);

  const processChartData = (data) => {
    const statusCounts = data.reduce((acc, report) => {
      acc[report.report_status] = (acc[report.report_status] || 0) + 1;
      return acc;
    }, {});

    const reportStatusChartData = Object.keys(statusCounts).map((key) => ({
      name: key,
      count: statusCounts[key],
    }));

    const scamCounts = data.reduce((acc, report) => {
      acc[report.scam_type] = (acc[report.scam_type] || 0) + 1;
      return acc;
    }, {});

    const scamTypeChartData = Object.keys(scamCounts).map((key, index) => ({
      name: key,
      value: scamCounts[key],
      color: COLORS[index % COLORS.length],
    }));

    setReportStatusData(reportStatusChartData);
    setScamTypeData(scamTypeChartData);
  };

  return (
  <div>
    <div className="bg-white p-4 sm:p-6 shadow rounded-lg mt-8">
      <h2 className="text-lg sm:text-xl font-semibold mb-4 flex items-center gap-2">
        <FiBarChart2 className="text-blue-500" /> Scam Reports Overview
      </h2>

      {/* Report Status Bar Chart */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }} 
        animate={{ opacity: 1, y: 0 }} 
        transition={{ duration: 0.5 }}
        className="w-full"
      >
        <h3 className="text-md sm:text-lg font-semibold text-gray-600 mb-3">Report Status Distribution</h3>
        <ResponsiveContainer width="100%" height={window.innerWidth < 640 ? 400 : 300}>
          <BarChart data={reportStatusData} margin={{ top: 10, right: 10, left: -20, bottom: 10 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" tick={{ fontSize: window.innerWidth < 640 ? 10 : 14, wordWrap: "break-word" }} />
            <YAxis tick={{ fontSize: window.innerWidth < 640 ? 10 : 14 }} />
            <Tooltip wrapperStyle={{ fontSize: "12px" }} />
            <Bar dataKey="count" fill="#8884d8" barSize={window.innerWidth < 640 ? 50 : 30} />
          </BarChart>
        </ResponsiveContainer>
      </motion.div>
    </div>
    <div className="bg-white p-4 sm:p-6 shadow rounded-lg mt-8 mb-6">
      {/* Scam Type Pie Chart */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }} 
        animate={{ opacity: 1, y: 0 }} 
        transition={{ duration: 0.5, delay: 0.2 }}
        className="mt-8"
      >
        <h3 className="text-md sm:text-lg font-semibold text-gray-600 mb-3">Scam Type Distribution</h3>
        <ResponsiveContainer width="100%" height={window.innerWidth < 640 ? 400 : 350}>
          <PieChart>
            <Pie 
              data={scamTypeData} 
              dataKey="value" 
              nameKey="name" 
              outerRadius={window.innerWidth < 640 ? 100 : 140} 
              labelLine={false} 
              label={({ name, percent }) => window.innerWidth < 640 ? null : `${name}: ${(percent * 100).toFixed(0)}%`}
            >
              {scamTypeData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip wrapperStyle={{ fontSize: "12px" }} />
            <Legend 
              layout={window.innerWidth < 640 ? "horizontal" : "vertical"} 
              align={window.innerWidth < 640 ? "left" : "right"} 
              verticalAlign={window.innerWidth < 640 ? "bottom" : "middle"} 
              wrapperStyle={{ fontSize: 12 }}
            />
          </PieChart>
        </ResponsiveContainer>
      </motion.div>
    </div>
  </div>
  );
};

export default WithAuth(ScamReportsChart);
