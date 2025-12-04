import React, { useState } from "react";
import axios from "../../../utils/axios";
import { Form, Input, Select, Button, message } from "antd";
import { motion } from "framer-motion";
import WithAuth from "../../hooks/WithAuth";


const { Item } = Form;
const { Option } = Select;

const BlockUnblockUser = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);

  // Handle form submission
  const handleSubmit = async (values) => {
    const { identifier, status } = values;

    try {
      setLoading(true);
      const response = await axios.put("/api/users/status", {
        identifier: identifier.toLowerCase(), // Convert to lowercase
        status,
      });

      if (response.data) {
        message.success(`User status updated to ${status} successfully!`);
        form.resetFields(); // Reset the form
      }
    } catch (error) {
      console.error("Error updating user status:", error);
      message.error("Failed to update user status. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: -20 }} 
      animate={{ opacity: 1, y: 0 }} 
      transition={{ duration: 0.5 }}
      style={{ maxWidth: 500, margin: "0 auto", padding: 20, borderRadius: 10, boxShadow: "0px 4px 10px rgba(0, 0, 0, 0.1)", background: "white" }}
    >
      <h2 style={{ textAlign: "center", marginBottom: 20 }}>Block/Unblock User</h2>
      <Form form={form} onFinish={handleSubmit}>
        {/* Email or User ID Input */}
        <Item
          name="identifier"
          label="Email or User ID"
          rules={[{ required: true, message: "Please enter the email or user ID" }]}
        >
          <motion.div whileHover={{ scale: 1.02 }}>
            <Input 
              placeholder="Enter email or user ID" 
              onChange={(e) => form.setFieldsValue({ identifier: e.target.value.toLowerCase() })} // Auto-lowercase
              style={{ transition: "0.3s", borderRadius: 8, border: "1px solid #ccc", padding: "8px" }}
            />
          </motion.div>
        </Item>

        {/* Status Selector */}
        <Item
          name="status"
          label="Status"
          rules={[{ required: true, message: "Please select a status" }]}
        >
          <Select placeholder="Select status" style={{ width: 200 }}>
            <Option value="active">Active</Option>
            <Option value="banned">Banned</Option>
          </Select>
        </Item>

        {/* Submit Button */}
        <Item>
          <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
            <Button type="primary" htmlType="submit" loading={loading} style={{ width: "100%", borderRadius: 8 }}>
              Update Status
            </Button>
          </motion.div>
        </Item>
      </Form>
    </motion.div>
  );
};

export default WithAuth(BlockUnblockUser);
