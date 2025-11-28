export async function healthCheck() {
  const res = await fetch('http://localhost:8000/health');
  return res.json();
}
