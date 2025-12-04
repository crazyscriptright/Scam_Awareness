import React, { useState, useEffect } from "react";
import axios from "../../utils/axios";
import { Table, Input, Button, Modal, Spin, message as antdMessage } from "antd";
import { FaSyncAlt, FaEye, FaPaperclip } from "react-icons/fa";
import { motion } from "framer-motion";
import dayjs from "dayjs";
import ModalImage from "react-modal-image";
import { Viewer, Worker } from "@react-pdf-viewer/core";
import "@react-pdf-viewer/core/lib/styles/index.css";
import WithAuth from "../hooks/WithAuth";


const ContactUsView = () => {
  const [contacts, setContacts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [selectedMessage, setSelectedMessage] = useState(null);
  const [modalVisible, setModalVisible] = useState(false);
  const [proofModalVisible, setProofModalVisible] = useState(false);
  const [attachment, setAttachment] = useState(null);

  useEffect(() => {
    fetchContacts();
  }, []);

  const fetchContacts = async () => {
    setLoading(true);
    try {
      const res = await axios.get("/api/contacts");
      setContacts(res.data);
    } catch (error) {
      console.error("Error fetching contacts:", error);
      antdMessage.error("Failed to fetch contact messages.");
    }
    setLoading(false);
  };

  const handleOpenModal = (message) => {
    setSelectedMessage(message);
    setModalVisible(true);
  };

  const filteredContacts = contacts.filter(
    (contact) =>
      contact.message.toLowerCase().includes(search.toLowerCase()) ||
      String(contact.contact_id).includes(search)
  );

  const fetchattachments = async (contactId) => {
    try {
      const res = await axios.get(`/api/contacts/${contactId}/attachment`);
      setAttachment(res.data);
      setProofModalVisible(true);
    } catch (error) {
      console.error("Error fetching attachment:", error);
      antdMessage.error("Failed to fetch attachment.");
    }
  };

  const getattachmentType = (attachment) => {
    if (typeof attachment === "string") {
      if (attachment.startsWith("data:image")) {
        return "image";
      } else if (attachment.startsWith("data:application")) {
        return "application";
      }
    }
    return "unknown";
  };

  const attachmentType = getattachmentType(attachment);

  const columns = [
    {
      title: "Contact ID",
      dataIndex: "contact_id",
      key: "contact_id",
      sorter: (a, b) => a.contact_id - b.contact_id,
    },
    {
      title: "User ID",
      dataIndex: "user_id",
      key: "user_id",
    },
    {
      title: "Submitted At",
      dataIndex: "submitted_at",
      key: "submitted_at",
      sorter: (a, b) => new Date(a.submitted_at) - new Date(b.submitted_at),
      render: (text) => dayjs(text).format("YYYY-MM-DD | HH:mm:ss"),
    },
    {
      title: "Message",
      dataIndex: "message",
      key: "message",
      render: (text) => (
        <div>
          {text.length > 15 ? (
            <>
              {text.substring(0, 15)}...
              <Button type="link" icon={<FaEye />} onClick={() => handleOpenModal(text)} />
            </>
          ) : (
            text
          )}
        </div>
      ),
    },
    {
      title: "Attachment",
      dataIndex: "attachment",
      key: "attachment",
      render: (attachment, record) =>
        attachment ? (
          <Button
            type="link"
            icon={<FaEye />}
            onClick={() => fetchattachments(record.contact_id)}
          >
            View
          </Button>
        ) : (
          "No Attachment"
        ),
    },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      className="bg-white rounded-xl shadow-md overflow-x-auto p-4 mt-8"
    >
      {/* Header */}
      <div className="flex flex-wrap justify-between items-center mb-4">
        <h2 className="text-lg md:text-2xl font-bold">Contact Messages</h2>
        <Button type="primary" icon={<FaSyncAlt />} onClick={fetchContacts} loading={loading}>
          Refresh
        </Button>
      </div>

      {/* Search Bar */}
      <Input
        placeholder="Search by Contact ID or Message"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="mb-4 p-2 border border-gray-300 rounded-lg"
      />

      {/* Table */}
      {loading ? (
        <div className="flex justify-center">
          <Spin tip="Loading messages..." />
        </div>
      ) : (
        <Table
          columns={columns}
          dataSource={filteredContacts}
          rowKey="contact_id"
          pagination={{ pageSize: 5 }}
        />
      )}

      {/* Message Modal */}
      <Modal
        title="Full Message"
        visible={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={null}
      >
        <p>{selectedMessage}</p>
      </Modal>

      {/* Attachment Modal */}
      <Modal
        title="Attachment"
        visible={proofModalVisible}
        onCancel={() => setProofModalVisible(false)}
        footer={null}
        width={800}
      >
        {attachment && (
          <div>
            {attachmentType === "image" ? (
              <ModalImage
                small={attachment}
                large={attachment}
                alt="Attachment"
                hideDownload={true}
              />
            ) : attachmentType === "application" ? (
              <Worker workerUrl="https://unpkg.com/pdfjs-dist@3.4.120/build/pdf.worker.min.js">
                <Viewer fileUrl={attachment} />
              </Worker>
            ) : (
              <p>Unknown attachment type.</p>
            )}
          </div>
        )}
      </Modal>
    </motion.div>
  );
};

export default WithAuth(ContactUsView);