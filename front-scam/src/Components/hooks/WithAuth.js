import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "../../utils/axios";
import { isAuthenticated, clearAuth } from "../../utils/auth";
import Loading from "../Loading";

const WithAuth = (WrappedComponent) => {
  const AuthComponent = (props) => {
    const [authStatus, setAuthStatus] = useState("checking"); // 'checking', 'authenticated', 'denied'
    const navigate = useNavigate();

    useEffect(() => {
      const verifyAuth = async () => {
        // First check if token exists and is valid (client-side)
        if (!isAuthenticated()) {
          setAuthStatus("denied");
          navigate("/login");
          return;
        }

        // Verify with backend that token is valid and user is admin
        try {
          const response = await axios.get("/api/verify-token");
          
          if (response.data.valid && response.data.user?.userType === 1) {
            setAuthStatus("authenticated");
          } else {
            clearAuth();
            setAuthStatus("denied");
            navigate("/login");
          }
        } catch (err) {
          console.error("Token verification error", err);
          clearAuth();
          setAuthStatus("denied");
          navigate("/login");
        }
      };

      verifyAuth();
    }, [navigate]);

    if (authStatus === "checking") {
      return <Loading />;
    }

    if (authStatus === "denied") {
      return null; // Already redirected, but could show a message briefly
    }

    return <WrappedComponent {...props} />;
  };

  return AuthComponent;
};

export default WithAuth;