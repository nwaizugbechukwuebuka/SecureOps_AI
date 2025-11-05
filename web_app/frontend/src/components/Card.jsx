import React from 'react';

export default function Card({ title, value, icon, color = 'default' }) {
  return (
    <div className={`card card-${color}`}>
      <div className="card-header">
        <span className="card-icon">{icon}</span>
        <h3 className="card-title">{title}</h3>
      </div>
      <div className="card-body">
        <div className="card-value">{value}</div>
      </div>
    </div>
  );
}