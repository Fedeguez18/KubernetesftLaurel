const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();
const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:3000';

app.use('/api', createProxyMiddleware({ target: BACKEND_URL, changeOrigin: true }));

app.use(express.static(path.join(__dirname, 'public')));

app.listen(8080, () => console.log('Frontend listening on 8080, proxy ->', BACKEND_URL));