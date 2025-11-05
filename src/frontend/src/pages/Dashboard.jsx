import React, { useEffect, useState } from 'react';
import { api, getWebSocketUrl } from '../services/api';

export default function Dashboard() {
  const [metrics, setMetrics] = useState({});
  const [celery, setCelery] = useState([]);
  const [redis, setRedis] = useState(null);
  const [prometheus, setPrometheus] = useState(null);

  useEffect(() => {
    // Fetch initial metrics
    api.get('/metrics').then(res => setMetrics(res.data));
    api.get('/celery/tasks').then(res => setCelery(res.data));
    api.get('/redis/info').then(res => setRedis(res.data));
    api.get('/prometheus/metrics').then(res => setPrometheus(res.data));

    // WebSocket for real-time updates
    const ws = new WebSocket(getWebSocketUrl('/ws/updates'));
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.metrics) setMetrics(data.metrics);
      if (data.celery) setCelery(data.celery);
      if (data.redis) setRedis(data.redis);
      if (data.prometheus) setPrometheus(data.prometheus);
    };
    return () => ws.close();
  }, []);

  return (
    <div className="dashboard">
      <h1>SecureOps Dashboard</h1>
      <section>
        <h2>System Metrics</h2>
        <pre>{JSON.stringify(metrics, null, 2)}</pre>
      </section>
      <section>
        <h2>Celery Tasks</h2>
        <pre>{JSON.stringify(celery, null, 2)}</pre>
      </section>
      <section>
        <h2>Redis Data</h2>
        <pre>{JSON.stringify(redis, null, 2)}</pre>
      </section>
      <section>
        <h2>Prometheus Metrics</h2>
        <pre>{JSON.stringify(prometheus, null, 2)}</pre>
      </section>
    </div>
  );
}
