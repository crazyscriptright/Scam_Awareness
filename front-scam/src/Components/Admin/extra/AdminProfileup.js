
// #####################3

import React, { useState } from "react";
import axios from "../../../utils/axios";

const AdminProfileup = () => {
  const [file, setFile] = useState(null);

  const handleFileChange = (e) => {
    const reader = new FileReader();
    reader.readAsDataURL(e.target.files[0]);
    reader.onload = () => {
      setFile(reader.result.split(",")[1]); // Extract Base64 part
    };
  };

  const handleUpload = async () => {
    if (!file) {
      alert("Please select a file first.");
      return;
    }

    try {
      await axios.post("/profile-picture", { profile_picture: file });

      alert("Profile picture uploaded successfully!");
    } catch (error) {
      console.error("Error uploading file:", error);
      alert("Error uploading profile picture.");
    }
  };

  return (
    <div>
      <input type="file" onChange={handleFileChange} />
      <button onClick={handleUpload}>Upload Profile Picture</button>
    </div>
  );
};

export default AdminProfileup;
