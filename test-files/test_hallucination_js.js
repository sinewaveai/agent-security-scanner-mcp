// Test file for JavaScript/npm package hallucination detection
// Mix of real and fake packages

// Real packages (should be found in npm)
const express = require('express');
const lodash = require('lodash');
const axios = require('axios');
import React from 'react';
import { useState } from 'react';

// Fake/hallucinated packages (should be detected)
const superAiHelper = require('super-ai-helper-magic');
const ultraParser = require('ultra-data-parser-fake');
import AwesomeMLUtils from 'awesome-ml-utils-notreal';
import MagicHttpClient from 'magic-http-client-xyz';
const flutterBridge = require('flutter-js-bridge-fake');
