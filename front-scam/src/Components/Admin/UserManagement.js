import WithAuth from "../hooks/WithAuth";
import React, { useState } from "react";
import axios from "../../utils/axios";
import { Form, Input, DatePicker, Button, message, Row, Col, Select } from "antd";
import { motion } from "framer-motion"; // For animations
import { 
  UserOutlined, 
  CalendarOutlined, 
  MailOutlined, 
  LockOutlined, 
  IdcardOutlined, 
  InfoCircleOutlined 
} from "@ant-design/icons"; // For icons
import dayjs from "dayjs"; // For date formatting

const { Item } = Form;
const { Password, TextArea } = Input;
const { Option } = Select;

const UserManagement = () => {
  const [createUserForm] = Form.useForm();
  const [blockUnblockForm] = Form.useForm();
  const [createUserLoading, setCreateUserLoading] = useState(false);
  const [blockUnblockLoading, setBlockUnblockLoading] = useState(false);

  // Handle Create External User form submission
  const handleCreateUserSubmit = async (values) => {
    const { name, dob, email, password } = values;

    try {
      setCreateUserLoading(true);
      const response = await axios.post("/api/create_external_user", {
        name,
        dob: dayjs(dob).format("YYYY-MM-DD"), // Format date
        email: email.toLowerCase(), // Convert email to lowercase
        password,
      });

      if (response.data) {
        message.success("User created successfully!");
        createUserForm.resetFields(); // Reset the form
      }
    } catch (error) {
      console.error("Error creating user:", error);
      message.error("Failed to create user. Please try again.");
    } finally {
      setCreateUserLoading(false);
    }
  };

  // Handle Block/Unblock User form submission
  const handleBlockUnblockSubmit = async (values) => {
    const { identifier, status, description } = values;

    try {
      setBlockUnblockLoading(true);
      const response = await axios.put("/api/users/status", {
        identifier: identifier.toLowerCase(), // Convert to lowercase
        status,
        description, // Optional description
      });

      if (response.data) {
        message.success(`User status updated to ${status} successfully!`);
        blockUnblockForm.resetFields(); // Reset the form
      }
    } catch (error) {
      console.error("Error updating user status:", error);
      message.error("Failed to update user status. Please try again.");
    } finally {
      setBlockUnblockLoading(false);
    }
  };

  // Convert email input to lowercase as the user types
  const handleEmailChange = (e) => {
    const lowercaseEmail = e.target.value.toLowerCase();
    createUserForm.setFieldsValue({ email: lowercaseEmail });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: -20 }} // Initial animation state
      animate={{ opacity: 1, y: 0 }} // Animate to this state
      transition={{ duration: 0.5 }} // Animation duration
      className="mt-8"
    >
      <Row gutter={[24, 24]} className="flex flex-wrap">
        {/* Create External User Column */}
        <Col xs={24} md={12} className="w-full md:w-1/2">
          <motion.div
            className="p-2 rounded-lg shadow-md bg-white"
          >
            <h2 className="text-center text-2xl font-bold mb-6">
              Create External User
            </h2>

            <Form form={createUserForm} onFinish={handleCreateUserSubmit}>
              {/* Name */}
              <Item
                name="name"
                label="Name"
                rules={[{ required: true, message: "Please enter the user's name" }]}
              >
                <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                  <Input 
                    placeholder="Enter name" 
                    prefix={<UserOutlined className="text-gray-400" />} 
                    className="w-full p-2 border rounded"
                  />
                </motion.div>
              </Item>

              {/* Date of Birth */}
              <Item
                name="dob"
                label="Date of Birth"
                rules={[{ required: true, message: "Please select the date of birth" }]}
              >
                <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                  <DatePicker 
                    className="w-full p-2 border rounded"
                    suffixIcon={<CalendarOutlined className="text-gray-400" />}
                    onChange={(date) => createUserForm.setFieldsValue({ dob: date })} // Bind the selected date to the form
                  />
                </motion.div>
              </Item>

              {/* Email */}
              <Item
                name="email"
                label="Email"
                rules={[
                  { required: true, message: "Please enter the user's email" },
                  { type: "email", message: "Please enter a valid email" },
                ]}
              >
                <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                  <Input
                    placeholder="Enter email"
                    prefix={<MailOutlined className="text-gray-400" />}
                    onChange={handleEmailChange} // Convert to lowercase as the user types
                    className="w-full p-2 border rounded"
                  />
                </motion.div>
              </Item>

              {/* Password */}
              <Item
                name="password"
                label="Password"
                rules={[{ required: true, message: "Please enter a password" }]}
              >
                <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                  <Password 
                    placeholder="Enter password" 
                    prefix={<LockOutlined className="text-gray-400" />}
                    className="w-full p-2 border rounded"
                  />
                </motion.div>
              </Item>

              {/* Submit Button */}
              <Item>
                <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                  <Button
                    type="primary"
                    htmlType="submit"
                    loading={createUserLoading}
                    className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600 transition"
                  >
                    Create External User
                  </Button>
                </motion.div>
              </Item>
            </Form>
          </motion.div>
        </Col>

        {/* Block/Unblock User Column */}
        <Col xs={24} md={12} className="w-full md:w-1/2">
          <motion.div
            className="p-4 rounded-lg shadow-md bg-white mt-6 lg:mt-0"
          >
            <h2 className="text-center text-2xl font-bold mb-6">Block/Unblock User</h2>
            <Form form={blockUnblockForm} onFinish={handleBlockUnblockSubmit}>
              {/* Email or User ID Input */}
              <Item
                name="identifier"
                label="Email or User ID"
                rules={[{ required: true, message: "Please enter the email or user ID" }]}
              >
                <motion.div whileHover={{ scale: 1.02 }}>
                  <Input
                    placeholder="Enter email or user ID"
                    prefix={<IdcardOutlined className="text-gray-400" />}
                    onChange={(e) =>
                      blockUnblockForm.setFieldsValue({ identifier: e.target.value.toLowerCase() })
                    } // Auto-lowercase
                    className="w-full p-2 border rounded"
                  />
                </motion.div>
              </Item>

              {/* Status Selector */}
              <Item
                name="status"
                label="Status"
                rules={[{ required: true, message: "Please select a status" }]}
              >
                <Select 
                  placeholder="Select status" 
                  className="w-full"
                  suffixIcon={<InfoCircleOutlined className="text-gray-400" />}
                >
                  <Option value="active">Active</Option>
                  <Option value="banned">Banned</Option>
                </Select>
              </Item>

              {/* Optional Description */}
              <Item
                name="description"
                label="Description"
              >
                <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                  <TextArea
                    placeholder="Enter description (optional)"
                    rows={4}
                    className="w-full p-2 border rounded"
                  />
                </motion.div>
              </Item>

              {/* Submit Button */}
              <Item>
                <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                  <Button
                    type="primary"
                    htmlType="submit"
                    loading={blockUnblockLoading}
                    className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600 transition"
                  >
                    Update Status
                  </Button>
                </motion.div>
              </Item>
            </Form>
          </motion.div>
        </Col>
      </Row>
    </motion.div>
  );
};

export default WithAuth(UserManagement);