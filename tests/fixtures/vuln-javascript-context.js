// Test fixture for context-aware filtering
// Lines that are import-only should NOT be flagged when they import known modules
// Lines with actual usage SHOULD still be flagged

const express = require('express');
const cp = require('child_process');
const path = require('path');
const helmet = require('helmet');

// These SHOULD be flagged - actual vulnerable usage
cp.exec("ls " + userInput);
element.innerHTML = userData;
const query = "SELECT * FROM users WHERE id = " + userId;
eval(userCode);
