import { useEffect, useState, useCallback } from "react";
import axios from "axios";

export interface AIThreat {
  event: any;
  threat_level: string;
  risk_score: number;
  anomaly_score: number;
  details: string;
}

export interface AIThreatSummary {
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export function useAIThreats(pipelineId: number) {
  const [threats, setThreats] = useState<AIThreat[]>([]);
  const [summary, setSummary] = useState<AIThreatSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchThreats = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await axios.get(`/api/pipelines/${pipelineId}/scans?limit=10`);
      const allThreats: AIThreat[] = [];
      let summaryAgg: AIThreatSummary = { count: 0, critical: 0, high: 0, medium: 0, low: 0 };
      res.data.forEach((scan: any) => {
        const ai = scan.results_summary?.ai_threats || [];
        const sum = scan.results_summary?.ai_threat_summary || {};
        allThreats.push(...ai);
        summaryAgg.count += sum.count || 0;
        summaryAgg.critical += sum.critical || 0;
        summaryAgg.high += sum.high || 0;
        summaryAgg.medium += sum.medium || 0;
        summaryAgg.low += sum.low || 0;
      });
      setThreats(allThreats);
      setSummary(summaryAgg);
    } catch (err: any) {
      setError(err.message || "Failed to load AI threats");
    } finally {
      setLoading(false);
    }
  }, [pipelineId]);

  useEffect(() => {
    fetchThreats();
    const interval = setInterval(fetchThreats, 30000);
    return () => clearInterval(interval);
  }, [fetchThreats]);

  return { threats, summary, loading, error, refetch: fetchThreats };
}
