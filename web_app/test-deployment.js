#!/usr/bin/env node
/**
 * Deployment verification script for SecureOps AI
 * Tests frontend and backend connectivity
 */

const https = require('https');
const http = require('http');

// Configuration
const FRONTEND_URL = 'https://nwaizugbechukwuebuka.github.io/SecureOps/';
const BACKEND_URL = 'https://secureops-ai-backend.onrender.com'; // Update with your backend URL
const HEALTH_ENDPOINT = '/health';

console.log('🔍 SecureOps AI - Deployment Verification\n');

// Test frontend
function testFrontend() {
    return new Promise((resolve, reject) => {
        console.log('🌐 Testing frontend deployment...');
        
        const req = https.get(FRONTEND_URL, (res) => {
            if (res.statusCode === 200) {
                console.log('✅ Frontend: GitHub Pages is accessible');
                console.log(`   URL: ${FRONTEND_URL}`);
                resolve(true);
            } else {
                console.log(`❌ Frontend: HTTP ${res.statusCode}`);
                reject(new Error(`Frontend returned ${res.statusCode}`));
            }
        });
        
        req.on('error', (error) => {
            console.log('❌ Frontend: Connection failed');
            console.log(`   Error: ${error.message}`);
            reject(error);
        });
        
        req.setTimeout(10000, () => {
            req.destroy();
            reject(new Error('Frontend request timeout'));
        });
    });
}

// Test backend
function testBackend() {
    return new Promise((resolve, reject) => {
        console.log('\n🔧 Testing backend API...');
        
        const url = `${BACKEND_URL}${HEALTH_ENDPOINT}`;
        const req = https.get(url, (res) => {
            let data = '';
            
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) {
                    try {
                        const health = JSON.parse(data);
                        console.log('✅ Backend: API is healthy');
                        console.log(`   URL: ${BACKEND_URL}`);
                        console.log(`   Status: ${health.status}`);
                        console.log(`   Service: ${health.service}`);
                        resolve(true);
                    } catch (e) {
                        console.log('⚠️  Backend: API responding but invalid JSON');
                        resolve(false);
                    }
                } else {
                    console.log(`❌ Backend: HTTP ${res.statusCode}`);
                    reject(new Error(`Backend returned ${res.statusCode}`));
                }
            });
        });
        
        req.on('error', (error) => {
            console.log('❌ Backend: Connection failed');
            console.log(`   Error: ${error.message}`);
            console.log('   💡 Make sure backend is deployed and running');
            reject(error);
        });
        
        req.setTimeout(10000, () => {
            req.destroy();
            reject(new Error('Backend request timeout'));
        });
    });
}

// Run tests
async function runTests() {
    let frontendOk = false;
    let backendOk = false;
    
    try {
        frontendOk = await testFrontend();
    } catch (error) {
        // Frontend test failed
    }
    
    try {
        backendOk = await testBackend();
    } catch (error) {
        // Backend test failed
    }
    
    console.log('\n📊 Deployment Status:');
    console.log(`Frontend (GitHub Pages): ${frontendOk ? '🟢 Online' : '🔴 Offline'}`);
    console.log(`Backend API: ${backendOk ? '🟢 Online' : '🔴 Offline'}`);
    
    if (frontendOk && backendOk) {
        console.log('\n🎉 SUCCESS: Your project is fully interconnected!');
        console.log('Frontend (GitHub Pages) + Backend (Cloud) = 100% Functional Web App');
        console.log(`\n🚀 Live Demo: ${FRONTEND_URL}`);
    } else {
        console.log('\n⚠️  PARTIAL SUCCESS: Some components need attention');
        console.log('See deployment instructions in README.md');
        
        if (!frontendOk) {
            console.log('\n🔧 Frontend fixes:');
            console.log('1. Check GitHub Pages is enabled in repository settings');
            console.log('2. Verify /docs folder contains index.html');
            console.log('3. Wait 2-3 minutes for GitHub Pages to update');
        }
        
        if (!backendOk) {
            console.log('\n🔧 Backend fixes:');
            console.log('1. Deploy backend to Render/Railway/Vercel');
            console.log('2. Update BACKEND_URL in this script');
            console.log('3. Check environment variables are set');
            console.log('4. Verify CORS origins include GitHub Pages domain');
        }
    }
}

runTests().catch(console.error);