import React, { useEffect, useState } from "react";
import axios from "../../../utils/axios";

const AdminProfileget = () => {
  const [image, setImage] = useState(null);

  useEffect(() => {
    axios
      .get("/profile-picture")
      .then((res) => {
        if (res.data.profile_picture) {
          setImage(`data:image/png;base64,${res.data.profile_picture}`);
        }
      })
      .catch((err) => console.error("Error fetching image:", err));
  }, []);

  return (
    <div>
      {image ? <img src={image} alt="Profile" width={200} height={200} /> : <p>No Profile Picture</p>}
    </div>
  );
};

export default AdminProfileget;