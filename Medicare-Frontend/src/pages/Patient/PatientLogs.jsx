import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { FileText, ClipboardList, RefreshCw, AlertTriangle, ShieldAlert } from "lucide-react";
import DashboardLayout from "../../components/DashboardLayout";
import PrimaryButton from "../../components/ui/PrimaryButton";
import { toast } from "react-hot-toast";
import api from "@/services/api";

const PatientLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const patientId = localStorage.getItem("id");

  const formatDate = (dateStr) =>
    new Date(dateStr).toLocaleString("en-IN", {
      dateStyle: "medium",
      timeStyle: "short",
    });

  // 🎨 Helper for Badge Colors
  const getTypeStyles = (type) => {
    switch (type?.toUpperCase()) {
      case "EMERGENCY":
        return "bg-red-100 text-red-700 border-red-200";
      case "REVOKE":
        return "bg-gray-100 text-gray-700 border-gray-200";
      case "ROUTINE":
      default:
        return "bg-green-100 text-green-700 border-green-200";
    }
  };

  const fetchLogs = async () => {
    try {
      const res = await api.get(`/access/logs/patient/${patientId}`);
      setLogs(res.data.logs || []);
    } catch (err) {
      toast.error("Failed to load activity logs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [patientId]);

  const handleReport = (logId) => {
    // Phase 2 Feature: This would open a dispute modal
    toast.success(`Access Log #${logId} flagged for review.`);
  };

  return (
    <DashboardLayout role="patient">
      <motion.div
        className="relative min-h-screen px-8 py-12 overflow-hidden"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
      >
        <div className="absolute inset-0 bg-gradient-to-br from-[#F0F8FF] via-[#EAF4FF] to-[#E1EEFF]" />
        
        <div className="relative z-10 max-w-6xl mx-auto">
          <div className="flex items-center justify-between mb-10">
            <div>
                <h1 className="text-4xl font-extrabold text-blue-900">Access Activity</h1>
                <p className="text-gray-600 mt-2">Monitor who is accessing your medical data.</p>
            </div>
            <PrimaryButton onClick={fetchLogs} className="w-auto px-4 py-2">
              <RefreshCw className="w-4 h-4 mr-2" /> Refresh
            </PrimaryButton>
          </div>

          <motion.div className="overflow-hidden rounded-2xl bg-white/80 backdrop-blur-xl shadow-lg border border-white/60">
            <table className="min-w-full text-sm text-left">
              <thead className="bg-blue-50/50 text-blue-900 font-bold uppercase tracking-wider">
                <tr>
                  <th className="py-4 px-6">Context</th>
                  <th className="py-4 px-6">Doctor</th>
                  <th className="py-4 px-6">Record</th>
                  <th className="py-4 px-6">Action</th>
                  <th className="py-4 px-6">Time</th>
                  <th className="py-4 px-6 text-center">Controls</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-blue-50/30 transition-colors">
                    <td className="py-4 px-6">
                      <span className={`px-3 py-1 rounded-full text-xs font-bold border ${getTypeStyles(log.access_type)}`}>
                        {log.access_type || "ROUTINE"}
                      </span>
                    </td>
                    <td className="py-4 px-6 font-medium text-gray-900">{log.doctor_name}</td>
                    <td className="py-4 px-6 text-gray-600 flex items-center gap-2">
                        <FileText className="w-4 h-4 text-blue-400"/> {log.record_name}
                    </td>
                    <td className="py-4 px-6 text-gray-700">{log.action}</td>
                    <td className="py-4 px-6 text-gray-500 font-mono text-xs">{formatDate(log.timestamp)}</td>
                    <td className="py-4 px-6 text-center">
                        <button 
                            onClick={() => handleReport(log.id)}
                            className="text-gray-400 hover:text-red-500 transition-colors"
                            title="Report Misuse"
                        >
                            <ShieldAlert className="w-5 h-5" />
                        </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {logs.length === 0 && !loading && (
                <div className="p-8 text-center text-gray-500">No activity recorded yet.</div>
            )}
          </motion.div>
        </div>
      </motion.div>
    </DashboardLayout>
  );
};

export default PatientLogs;