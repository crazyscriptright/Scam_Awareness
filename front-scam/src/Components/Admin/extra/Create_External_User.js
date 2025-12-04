import React, { useState } from "react";
import axios from "../../../utils/axios";
import { Form, Input, DatePicker, Button, message } from "antd";
import { motion } from "framer-motion"; // For animations
import { UserAddOutlined } from "@ant-design/icons"; // For icons
import WithAuth from "../../hooks/WithAuth";


const { Item } = Form;
const { Password } = Input;

const Create_External_User = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);

  // Handle form submission
  const handleSubmit = async (values) => {
    try {
      setLoading(true);
      const response = await axios.post(
        "/api/create_external_user",
        {
          name: values.name,
          dob: values.dob.format("YYYY-MM-DD"),
          email: values.email.toLowerCase(),
          password: values.password,
        },
        {
          headers: {
            "Content-Type": "application/json",
          },
          // withCredentials: true // Uncomment if using cookies
        }
      );
  
      if (response.data.success) {
        message.success("User created successfully!");
        form.resetFields();
      }
    } catch (error) {
      const errorMessage = error.response?.data?.message || error.message;
      message.error(`Error: ${errorMessage}`);
    } finally {
      setLoading(false);
    }
  };

  // Convert email input to lowercase as the user types
  const handleEmailChange = (e) => {
    const lowercaseEmail = e.target.value.toLowerCase();
    form.setFieldsValue({ email: lowercaseEmail });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: -20 }} // Initial animation state
      animate={{ opacity: 1, y: 0 }} // Animate to this state
      transition={{ duration: 0.5 }} // Animation duration
      style={{ maxWidth: 1000, margin: "70px", padding: 20, borderRadius: 10, boxShadow: "0px 4px 10px rgba(0, 0, 0, 0.1)",}}
    >
      <h2 style={{ textAlign: "center", marginBottom: 24 }}>
        <UserAddOutlined style={{ marginRight: 8 }} />
        Create External User
      </h2>

      <Form form={form} onFinish={handleSubmit}>
        {/* Name */}
        <Item
          name="name"
          label="Name"
          rules={[{ required: true, message: "Please enter the user's name" }]}
        >
          <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
            <Input placeholder="Enter name" />
          </motion.div>
        </Item>

        {/* Date of Birth */}
        <Item
          name="dob"
          label="Date of Birth"
          rules={[{ required: true, message: "Please select the date of birth" }]}
        >
          <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
            <DatePicker style={{ width: "100%" }} />
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
              onChange={handleEmailChange} // Convert to lowercase as the user types
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
            <Password placeholder="Enter password" />
          </motion.div>
        </Item>

        {/* Submit Button */}
        <Item>
          <motion.div
            whileHover={{ scale: 1.05 }} // Hover effect
            whileTap={{ scale: 0.95 }} // Click effect
          >
            <Button
              type="primary"
              htmlType="submit"
              loading={loading}
              style={{ width: "100%", marginTop: 16 }}
            >
              Create External User
            </Button>
          </motion.div>
        </Item>
      </Form>
    </motion.div>
  );
};

export default WithAuth(Create_External_User);