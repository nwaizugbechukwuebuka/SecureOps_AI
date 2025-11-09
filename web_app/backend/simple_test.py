#!/usr/bin/env python3
"""
Simple backend test for SecureOps AI
"""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Create FastAPI app
app = FastAPI(title="SecureOps AI Backend", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3010", "http://127.0.0.1:3010"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"message": "SecureOps AI Backend is running!"}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "SecureOps AI Backend"}


@app.get("/api/test")
async def api_test():
    return {"message": "API is working", "version": "1.0.0"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8010, reload=False)
