(function() {
    'use strict';
    console.log('[IVAC PANEL] Script started - Ultimate Enhanced Version v14.2');

    // Enhanced Configuration with 4 Family Members Structure
    let config = {
        appiDate: "2025-11-17",
        highcom: "1",
        ivac_id: "17",
        visa_type: "13",
        visit_purpose: "PURPOSE FOR MEDICAL TREATMENT",
        mobileNumber: "01997905875",
        password: "123456",
        emailname: "hazira.kes1990@gmail.com",
        fullname: "HAZIRA KHATUN",
        webid: "BGDDV8EC5225",
        webid_repeat: "BGDDV8EC5225",
        family: [
            //{ name: "SOFIQUL ISLAM", webfile_no: "BGDDV8EC7025", again_webfile_no: "BGDDV8EC7025"},
            //{ name: "PRIYANKA RANI", webfile_no: "BGDDV8E3FC25", again_webfile_no: "BGDDV8E3FC25"},
            //{ name: "NIHAR RANJAN", webfile_no: "BGDDV8E41025", again_webfile_no: "BGDDV8E41025"},
            //{ name: "NIHAR RANJAN", webfile_no: "BGDDV8E41025", again_webfile_no: "BGDDV8E41025"}
        ],
        rememberMe: true,
        familyCount: "0",
        defaultTime: "09:00 - 09:59",
        autoSelectFirstAvailable: true
    };

    const CAPTCHA_API_KEY = "CAP-1C86C39373F5716313CCE6D20EF6E1B852B882CBA836C0350B5B82FE3F45A70D";
    const CAPSOLVER_API_URL = "https://api.capsolver.com/createTask";
    const CAPSOLVER_GET_TASK_URL = "https://api.capsolver.com/getTaskResult";

    const SITE_KEYS = {
        login: "0x4AAAAAABpNUpzYeppBoYpe",
        application: "0x4AAAAAABvQ3Mi6RktCuZ7P",
        payNow: "0x4AAAAAABvQ3Mi6RktCuZ7P"
    };

    // Server Data Storage
    const serverData = {
        appointment_date: "",
        appointment_time_final: null,
        hash_param: null,
        selected_payment: {
            name: "VISA",
            slug: "visacard",
            link: "https://securepay.sslcommerz.com/gwprocess/v4/image/gw1/visa.png"
        },
        slot_times: [],
        payment_link: null,
        access_token: null,
        cookies: {},
        currentStep: 1,
        application_payload: null,
        personal_payload: null,
        overview_response: null,
        rateLimitReset: null,
        captcha_data: {
            captcha_id: null,
            captcha_image: null,
            captcha_solution: null,
            is_verified: false,
            generated_at: null
        },
        client_ip: null,
        ip_checked: false,
        token_data: {
            access_tokens: [],
            bearer_tokens: [],
            session_tokens: [],
            other_tokens: [],
            last_token_update: null
        },
        session_data: {
            session_id: null,
            login_timestamp: null,
            last_activity: null,
            is_logged_in: false,
            token_validated: false,
            cookies_snapshot: {}
        }
    };

    // Global Variables
    let importPopup, exportPopup, uploadPopup;
    const activeRequests = new Set();
    let currentTab = 'data-submit';

    // Rate Limit Variables
    let rateLimitTimer = null;
    let rateLimitSeconds = 0;

    // ==================== FIXED RESPONSE PARSING - PROPER SUCCESS DETECTION ====================
    function parseApiResponse(response) {
        if (!response) {
            return { success: false, message: 'No response received' };
        }

        console.log('[API RESPONSE] Raw response structure:', response);

        // Handle cases where response exists but no data
        if (!response.json && !response.data && !response.text) {
            return { 
                success: false, 
                message: 'No response data',
                rawResponse: response 
            };
        }

        // If we have text response with multiple JSON objects, parse them first
        if (response.text && typeof response.text === 'string') {
            console.log('[API RESPONSE] Text response detected:', response.text);
            
            try {
                // Parse the text response which contains multiple JSON objects
                const parsedTextResponse = parseTextResponse(response.text);
                response.json = parsedTextResponse;
                response.data = parsedTextResponse;
                console.log('[API RESPONSE] Parsed text response:', parsedTextResponse);
            } catch (e) {
                console.error('[API RESPONSE] Error parsing text response:', e);
            }
        }

        // Extract the data to parse - prefer response.json, fallback to response.data
        const dataToParse = response.json || response.data;

        // Handle array responses (like your example: 0:{...}, 1:{...})
        if (Array.isArray(dataToParse)) {
            console.log('[API RESPONSE] Array response detected:', dataToParse);
            
            // Look for success object in the array - check ALL objects
            for (let i = 0; i < dataToParse.length; i++) {
                const item = dataToParse[i];
                if (item && typeof item === 'object') {
                    // Check if this is a success response object - FIXED LOGIC
                    const isSuccess = item.status === 'success' || 
                                     item.status_code === 200 ||
                                     (item.message && item.message.includes('successfully'));
                    
                    if (isSuccess) {
                        const result = {
                            success: true,
                            status: item.status,
                            status_code: item.status_code,
                            message: item.message || 'Operation completed successfully',
                            data: item.data || {},
                            meta: item.meta || [],
                            fullResponse: dataToParse
                        };
                        console.log('[API RESPONSE] Success parsed from array:', result);
                        return result;
                    }
                    
                    // Also check for error responses
                    if (item.status === 'error' || (item.status_code && item.status_code >= 400)) {
                        const result = {
                            success: false,
                            status: item.status,
                            status_code: item.status_code,
                            message: item.message || 'Operation failed',
                            data: item.data || {},
                            meta: item.meta || [],
                            fullResponse: dataToParse
                        };
                        console.log('[API RESPONSE] Error parsed from array:', result);
                        return result;
                    }
                }
            }
            
            // If no status object found but we have array data, check if any object has success indicators
            const hasSuccessIndicator = dataToParse.some(item => 
                item && typeof item === 'object' && 
                (item.status === 'success' || item.status_code === 200 || 
                 (item.message && item.message.includes('successfully')))
            );
            
            if (hasSuccessIndicator) {
                const result = {
                    success: true,
                    message: 'Operation completed successfully',
                    fullResponse: dataToParse
                };
                console.log('[API RESPONSE] Array treated as success:', result);
                return result;
            }
            
            // Default to failure if no success indicators found
            const result = {
                success: false,
                message: 'Operation failed - no success indicators found',
                fullResponse: dataToParse
            };
            console.log('[API RESPONSE] Array treated as failure:', result);
            return result;
        }
        
        // Handle traditional object response
        if (dataToParse && typeof dataToParse === 'object') {
            // Check for success indicators - IMPROVED LOGIC
            const isSuccess = dataToParse.status === 'success' || 
                             dataToParse.status_code === 200 || 
                             dataToParse.success === true ||
                             (dataToParse.message && dataToParse.message.includes('successfully')) ||
                             (dataToParse.success === undefined && dataToParse.status === 'success');

            if (isSuccess) {
                const result = {
                    success: true,
                    status: dataToParse.status,
                    status_code: dataToParse.status_code,
                    message: dataToParse.message || 'Operation completed successfully',
                    data: dataToParse.data || {},
                    meta: dataToParse.meta || [],
                    fullResponse: dataToParse
                };
                console.log('[API RESPONSE] Object success parsed:', result);
                return result;
            } else {
                const result = {
                    success: false,
                    status: dataToParse.status,
                    status_code: dataToParse.status_code,
                    message: dataToParse.message || 'Operation failed',
                    data: dataToParse.data || {},
                    meta: dataToParse.meta || [],
                    fullResponse: dataToParse
                };
                console.log('[API RESPONSE] Object error parsed:', result);
                return result;
            }
        }

        // Fallback for unexpected response formats
        console.warn('[API RESPONSE] Unexpected response format:', response);
        return {
            success: false,
            message: 'Unexpected response format',
            rawResponse: response
        };
    }

    // NEW FUNCTION: Parse text response with multiple JSON objects - IMPROVED
    function parseTextResponse(text) {
        if (!text) return null;
        
        console.log('[TEXT PARSER] Raw text:', text);
        
        // Handle the specific format: "0:{"key":"value"}" by splitting properly
        const lines = text.split('\n').filter(line => line.trim());
        console.log('[TEXT PARSER] Lines found:', lines.length, lines);
        
        const parsedObjects = [];
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            
            try {
                let jsonString = line;
                
                // Handle the format like "0:{"key":"value"}" - IMPROVED PARSING
                const colonIndex = line.indexOf(':');
                if (colonIndex > 0) {
                    const prefix = line.substring(0, colonIndex);
                    // Check if prefix is a number (like "0", "1", etc.)
                    if (!isNaN(parseInt(prefix))) {
                        jsonString = line.substring(colonIndex + 1);
                    }
                }
                
                const parsed = JSON.parse(jsonString);
                parsedObjects.push(parsed);
                console.log(`[TEXT PARSER] Successfully parsed line ${i}:`, parsed);
            } catch (e) {
                console.warn(`[TEXT PARSER] Failed to parse line ${i}:`, line, 'Error:', e);
                // If JSON parsing fails, try to extract JSON-like objects with better regex
                const jsonMatch = line.match(/\{[\s\S]*\}/);
                if (jsonMatch) {
                    try {
                        const parsed = JSON.parse(jsonMatch[0]);
                        parsedObjects.push(parsed);
                        console.log(`[TEXT PARSER] Extracted JSON from line ${i}:`, parsed);
                    } catch (e2) {
                        console.warn(`[TEXT PARSER] Failed to extract JSON from line ${i}`);
                    }
                }
            }
        }
        
        // Return structure based on content
        if (parsedObjects.length === 1) {
            return parsedObjects[0];
        } else if (parsedObjects.length > 1) {
            return parsedObjects;
        }
        
        return null;
    }

    // ==================== FIXED CAPTCHA RESPONSE PARSER ====================
    function parseCaptchaResponse(response) {
        if (!response || !response.json) {
            return { success: false, message: 'No response data' };
        }

        console.log('[CAPTCHA PARSER] Raw response structure:', response.json);

        let captchaId = null;
        let captchaImage = null;
        let statusMessage = null;

        // Handle array response format (your case: Array(2))
        if (Array.isArray(response.json)) {
            console.log('[CAPTCHA PARSER] Processing as array response');
            
            response.json.forEach((item, index) => {
                console.log(`[CAPTCHA PARSER] Item ${index}:`, item);
                
                if (item && typeof item === 'object') {
                    // Check for success object with captcha data
                    if (item.status === 'success' && item.data) {
                        captchaId = item.data.captcha_id;
                        statusMessage = item.message;
                        console.log(`[CAPTCHA PARSER] Found success object with captcha_id: ${captchaId}`);
                    }
                    
                    // Check for image data in any object
                    if (item.data && item.data.captcha_image) {
                        captchaImage = item.data.captcha_image;
                        console.log(`[CAPTCHA PARSER] Found captcha_image in data`);
                    }
                    
                    // Also check for direct image data
                    if (item.captcha_image) {
                        captchaImage = item.captcha_image;
                        console.log(`[CAPTCHA PARSER] Found direct captcha_image`);
                    }
                }
            });
        }
        
        // Handle object response format
        else if (typeof response.json === 'object') {
            // Check for success object
            if (response.json.status === 'success' && response.json.data) {
                captchaId = response.json.data.captcha_id;
                captchaImage = response.json.data.captcha_image;
                statusMessage = response.json.message;
            }
            
            // Check numeric keys (0, 1, 2 format)
            if (response.json['1'] && response.json['1'].status === 'success') {
                const successObj = response.json['1'];
                captchaId = successObj.data?.captcha_id;
                statusMessage = successObj.message;
                captchaImage = successObj.data?.captcha_image;
            }
        }

        console.log('[CAPTCHA PARSER] Extraction results:', {
            hasCaptchaId: !!captchaId,
            hasCaptchaImage: !!captchaImage,
            captchaId: captchaId,
            imagePreview: captchaImage ? captchaImage.substring(0, 100) + '...' : 'No image'
        });

        if (captchaId) {
            return {
                success: true,
                captcha_id: captchaId,
                captcha_image: captchaImage,
                message: statusMessage || 'CAPTCHA generated successfully'
            };
        } else {
            return {
                success: false,
                message: 'Failed to extract CAPTCHA data from response',
                rawResponse: response.json
            };
        }
    }

    // ==================== NEW FUNCTION: FETCH CAPTCHA IMAGE ====================
    async function fetchCaptchaImage(captchaId) {
        if (!captchaId) {
            throw new Error('No captcha ID provided');
        }

        console.log(`[CAPTCHA] Fetching image for captcha_id: ${captchaId}`);
        
        try {
            const response = await doFetch('https://payment.ivacbd.com/application', {
                method: 'POST',
                headers: {
                    'accept': 'text/x-component',
                    'content-type': 'text/plain;charset=UTF-8',
                    'next-action': '70648dcd61dd835363065814f031d26034cc029dfa',
                    'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22(root)%22%2C%7B%22children%22%3A%5B%22application%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
                },
                body: JSON.stringify([captchaId, "$undefined", serverData.client_ip])
            });

            console.log('[CAPTCHA] Image fetch response:', response);
            
            if (response.ok && response.json) {
                // Try to extract image from the response
                let imageData = null;
                
                if (Array.isArray(response.json)) {
                    response.json.forEach(item => {
                        if (item && typeof item === 'object') {
                            if (item.data && item.data.captcha_image) {
                                imageData = item.data.captcha_image;
                            } else if (item.captcha_image) {
                                imageData = item.captcha_image;
                            }
                        } else if (typeof item === 'string' && item.includes('base64')) {
                            imageData = item;
                        }
                    });
                } else if (typeof response.json === 'object') {
                    imageData = response.json.data?.captcha_image || response.json.captcha_image;
                }
                
                if (imageData) {
                    console.log('[CAPTCHA] Successfully extracted image data');
                    return imageData;
                } else {
                    throw new Error('No image data found in response');
                }
            } else {
                throw new Error(`Image fetch failed: ${response.status}`);
            }
        } catch (error) {
            console.error('[CAPTCHA] Error fetching captcha image:', error);
            throw error;
        }
    }

    // ==================== ENHANCED STATUS MESSAGES ====================
    function setStatus(message, isError = false) {
        const statusElement = document.getElementById('ivac-status');
        const timestamp = new Date().toLocaleTimeString();
        const formattedMessage = `[${timestamp}] ${message}`;
        
        if (statusElement) {
            statusElement.textContent = formattedMessage;
            statusElement.style.background = isError ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)';
            statusElement.style.color = isError ? '#ef4444' : '#10b981';
        }
        
        // Always log to console with appropriate level
        if (isError) {
            console.error(`[IVAC PANEL] ${message}`);
        } else {
            console.log(`[IVAC PANEL] ${message}`);
        }
    }

    function setDetailedStatus(operation, response, parsedResponse) {
        const timestamp = new Date().toLocaleTimeString();
        let statusMessage = '';
        
        if (parsedResponse.success) {
            statusMessage = `✅ ${operation} SUCCESS`;
            if (parsedResponse.message) {
                statusMessage += ` | ${parsedResponse.message}`;
            }
            if (parsedResponse.data) {
                // Add relevant data points to status
                if (parsedResponse.data.payable_amount) {
                    statusMessage += ` | Payable: ${parsedResponse.data.payable_amount} BDT`;
                }
                if (parsedResponse.data.visa_fees) {
                    statusMessage += ` | Visa Fees: ${parsedResponse.data.visa_fees} BDT`;
                }
                if (parsedResponse.data.webfile_count) {
                    statusMessage += ` | Webfiles: ${parsedResponse.data.webfile_count}`;
                }
                if (parsedResponse.data.slot_dates) {
                    statusMessage += ` | Available Dates: ${parsedResponse.data.slot_dates.join(', ')}`;
                }
            }
        } else {
            statusMessage = `❌ ${operation} FAILED`;
            if (parsedResponse.message) {
                statusMessage += ` | ${parsedResponse.message}`;
            }
            if (parsedResponse.status_code) {
                statusMessage += ` | Code: ${parsedResponse.status_code}`;
            }
        }
        
        setStatus(statusMessage, !parsedResponse.success);
        
        // Detailed console logging
        console.group(`📡 ${operation} - ${timestamp}`);
        console.log('🔹 Request Details:', {
            url: response?.url || 'N/A',
            method: response?.method || 'N/A',
            status: response?.status || 'N/A',
            statusText: response?.statusText || 'N/A'
        });
        console.log('🔹 Parsed Response:', parsedResponse);
        console.log('🔹 Full Response:', response);
        console.groupEnd();
    }

    function setCapSolverStatus(message, isError = false) {
        const statusElement = document.getElementById('capsolver-status');
        if (statusElement) {
            statusElement.textContent = `CapSolver: ${message}`;
            statusElement.style.color = isError ? '#ef4444' : '#fbbf24';
        }
        console.log(`[CAPSOLVER] ${message}`);
    }

    // ==================== ULTIMATE TOKEN & COOKIE MANAGEMENT ====================
    function getAllCookies() {
        const cookies = {};
        try {
            document.cookie.split(';').forEach(cookie => {
                const [key, value] = cookie.trim().split('=');
                if (key && value) {
                    cookies[key] = decodeURIComponent(value);
                }
            });
        } catch (e) {
            console.error('Error reading cookies:', e);
        }
        return cookies;
    }

    function getCookie(name) {
        const cookies = getAllCookies();
        return cookies[name] || null;
    }

    function setCookie(name, value, days = 1) {
        try {
            const date = new Date();
            date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
            const expires = "expires=" + date.toUTCString();
            document.cookie = `${name}=${encodeURIComponent(value)}; ${expires}; path=/; secure; samesite=lax`;
            return true;
        } catch (e) {
            console.error('Error setting cookie:', e);
            return false;
        }
    }

    function extractTokensFromCookies() {
        const cookies = getAllCookies();
        const tokens = {
            access_tokens: [],
            bearer_tokens: [],
            session_tokens: [],
            other_tokens: []
        };

        // Pattern matching for different token types
        const tokenPatterns = {
            access_tokens: [/access[_-]?token/i, /token/i, /auth[_-]?token/i],
            bearer_tokens: [/bearer/i],
            session_tokens: [/session/i, /sessid/i, /ivac[_-]?session/i]
        };

        Object.entries(cookies).forEach(([key, value]) => {
            // Check for access tokens
            if (tokenPatterns.access_tokens.some(pattern => pattern.test(key))) {
                tokens.access_tokens.push({ key, value, source: 'cookie' });
                console.log(`[TOKEN] Found access token: ${key}`);
            }

            // Check for bearer tokens
            if (tokenPatterns.bearer_tokens.some(pattern => pattern.test(key))) {
                tokens.bearer_tokens.push({ key, value, source: 'cookie' });
                console.log(`[TOKEN] Found bearer token: ${key}`);
            }

            // Check for session tokens
            if (tokenPatterns.session_tokens.some(pattern => pattern.test(key))) {
                tokens.session_tokens.push({ key, value, source: 'cookie' });
                console.log(`[TOKEN] Found session token: ${key}`);
            }

            // Check if value itself looks like a JWT token
            if (value && value.length > 100 && value.includes('.')) {
                const parts = value.split('.');
                if (parts.length === 3) {
                    tokens.other_tokens.push({ key, value, source: 'cookie', type: 'jwt' });
                    console.log(`[TOKEN] Found JWT token: ${key}`);
                }
            }
        });

        return tokens;
    }

    function extractTokenFromHeaders(headers) {
        const tokens = [];

        if (headers instanceof Headers) {
            // Check Authorization header
            const authHeader = headers.get('authorization');
            if (authHeader && authHeader.startsWith('Bearer ')) {
                const token = authHeader.replace('Bearer ', '');
                tokens.push({
                    type: 'bearer',
                    value: token,
                    source: 'response_header',
                    header: 'authorization'
                });
                console.log('[TOKEN] Found Bearer token in headers');
            }

            // Check other potential token headers
            const tokenHeaders = ['x-access-token', 'x-auth-token', 'token', 'access-token'];
            tokenHeaders.forEach(headerName => {
                const headerValue = headers.get(headerName);
                if (headerValue) {
                    tokens.push({
                        type: 'access',
                        value: headerValue,
                        source: 'response_header',
                        header: headerName
                    });
                    console.log(`[TOKEN] Found token in ${headerName} header`);
                }
            });
        }

        return tokens;
    }

    function extractTokenFromResponseData(data) {
        const tokens = [];

        if (!data) return tokens;

        // Recursive function to search for tokens in objects/arrays
        function searchForTokens(obj, path = '') {
            if (!obj || typeof obj !== 'object') return;

            if (Array.isArray(obj)) {
                obj.forEach((item, index) => searchForTokens(item, `${path}[${index}]`));
                return;
            }

            Object.entries(obj).forEach(([key, value]) => {
                const currentPath = path ? `${path}.${key}` : key;

                // Check if this is a token field
                if (typeof value === 'string' && value.length > 20) {
                    const lowerKey = key.toLowerCase();

                    // Access token patterns
                    if (lowerKey.includes('access') && lowerKey.includes('token')) {
                        tokens.push({
                            type: 'access',
                            value: value,
                            source: 'response_body',
                            path: currentPath
                        });
                        console.log(`[TOKEN] Found access token at: ${currentPath}`);
                    }

                    // Bearer token patterns
                    else if (lowerKey.includes('bearer') || lowerKey.includes('auth')) {
                        tokens.push({
                            type: 'bearer',
                            value: value,
                            source: 'response_body',
                            path: currentPath
                        });
                        console.log(`[TOKEN] Found bearer token at: ${currentPath}`);
                    }

                    // JWT token detection
                    else if (value.includes('.') && value.length > 100) {
                        const parts = value.split('.');
                        if (parts.length === 3) {
                            tokens.push({
                                type: 'jwt',
                                value: value,
                                source: 'response_body',
                                path: currentPath
                            });
                            console.log(`[TOKEN] Found JWT token at: ${currentPath}`);
                        }
                    }
                }

                // Recursively search nested objects
                if (value && typeof value === 'object') {
                    searchForTokens(value, currentPath);
                }
            });
        }

        searchForTokens(data);
        return tokens;
    }

    function updateTokensFromResponse(response, responseData) {
        if (!response) return;

        const newTokens = [];

        // Extract from cookies
        const cookieTokens = extractTokensFromCookies();
        newTokens.push(...cookieTokens.access_tokens, ...cookieTokens.bearer_tokens, ...cookieTokens.session_tokens);

        // Extract from response headers
        const headerTokens = extractTokenFromHeaders(response.headers);
        newTokens.push(...headerTokens);

        // Extract from response body
        const bodyTokens = extractTokenFromResponseData(responseData);
        newTokens.push(...bodyTokens);

        // Update serverData with new tokens
        newTokens.forEach(token => {
            if (token.type === 'access' || token.source === 'response_body') {
                if (!serverData.token_data.access_tokens.some(t => t.value === token.value)) {
                    serverData.token_data.access_tokens.push(token);
                    serverData.access_token = token.value; // Set as primary access token
                    console.log(`[TOKEN] Set primary access token: ${token.value.substring(0, 20)}...`);
                }
            }

            if (token.type === 'bearer') {
                if (!serverData.token_data.bearer_tokens.some(t => t.value === token.value)) {
                    serverData.token_data.bearer_tokens.push(token);
                }
            }
        });

        serverData.token_data.last_token_update = Date.now();

        if (newTokens.length > 0) {
            console.log(`[TOKEN] Updated tokens: ${newTokens.length} new tokens found`);
            updateTokenDisplay();
        }
    }

    function updateTokenDisplay() {
        const tokenStatus = document.getElementById('token-status');
        if (tokenStatus) {
            const tokenCount = serverData.token_data.access_tokens.length;
            if (tokenCount > 0) {
                tokenStatus.textContent = `Active (${tokenCount} tokens)`;
                tokenStatus.style.color = '#10b981';
            } else {
                tokenStatus.textContent = 'No tokens';
                tokenStatus.style.color = '#ef4444';
            }
        }
    }

    // ==================== ENHANCED SESSION MANAGEMENT ====================
    function saveSession() {
        try {
            const currentCookies = getAllCookies();
            const tokens = extractTokensFromCookies();

            const sessionData = {
                access_token: serverData.access_token,
                cookies: currentCookies,
                session_id: serverData.session_data.session_id,
                last_activity: Date.now(),
                user_agent: navigator.userAgent,
                login_timestamp: serverData.session_data.login_timestamp,
                is_logged_in: serverData.session_data.is_logged_in,
                cookies_snapshot: currentCookies,
                token_data: serverData.token_data
            };

            localStorage.setItem('ivac_session', JSON.stringify(sessionData));
            console.log('[SESSION] Session saved with tokens:', serverData.token_data.access_tokens.length);
            return true;
        } catch (e) {
            console.error('Error saving session:', e);
            return false;
        }
    }

    function loadSession() {
        try {
            const saved = localStorage.getItem('ivac_session');
            if (saved) {
                const sessionData = JSON.parse(saved);

                // Check if session is still valid (less than 8 hours old)
                const sessionAge = Date.now() - sessionData.last_activity;
                const maxSessionAge = 8 * 60 * 60 * 1000;

                if (sessionAge < maxSessionAge && sessionData.user_agent === navigator.userAgent) {
                    // Restore session data
                    serverData.access_token = sessionData.access_token;
                    serverData.cookies = sessionData.cookies || {};
                    serverData.session_data.session_id = sessionData.session_id;
                    serverData.session_data.login_timestamp = sessionData.login_timestamp;
                    serverData.session_data.last_activity = Date.now();
                    serverData.session_data.cookies_snapshot = sessionData.cookies_snapshot || {};
                    serverData.token_data = sessionData.token_data || serverData.token_data;

                    // Restore cookies to document
                    Object.entries(serverData.cookies).forEach(([key, value]) => {
                        setCookie(key, value);
                    });

                    console.log('[SESSION] Session restored with tokens:', serverData.token_data.access_tokens.length);

                    // Validate session
                    if (validateSession()) {
                        serverData.session_data.is_logged_in = true;
                        serverData.session_data.token_validated = true;
                        return true;
                    }
                } else {
                    console.log('[SESSION] Session expired');
                    clearSession();
                }
            }
        } catch (e) {
            console.error('Error loading session:', e);
        }
        return false;
    }

    function validateSession() {
        // Check if we have valid tokens
        if (serverData.token_data.access_tokens.length > 0 && serverData.access_token) {
            console.log('[SESSION] Validated via tokens');
            return true;
        }

        // Check cookies for authentication indicators
        const cookies = getAllCookies();
        const authCookies = Object.keys(cookies).filter(key =>
            key.includes('token') ||
            key.includes('session') ||
            key.includes('auth') ||
            key.includes('ivac')
        );

        if (authCookies.length > 0) {
            console.log('[SESSION] Validated via auth cookies:', authCookies);
            return true;
        }

        // Check page content for login state
        if (detectLoginFromPage()) {
            console.log('[SESSION] Validated via page content');
            return true;
        }

        return false;
    }

    function detectLoginFromPage() {
        const indicators = [
            document.querySelector('[href*="logout"]'),
            document.querySelector('[onclick*="logout"]'),
            document.querySelector('.user-info'),
            document.querySelector('.profile'),
            document.querySelector('[class*="dashboard"]'),
            document.querySelector('[class*="welcome"]'),
            document.body.innerHTML.includes('logout'),
            document.body.innerHTML.includes('dashboard'),
            document.body.innerHTML.includes('profile')
        ];

        return indicators.some(indicator => indicator !== null && indicator !== false);
    }

    function clearSession() {
        serverData.access_token = null;
        serverData.cookies = {};
        serverData.token_data.access_tokens = [];
        serverData.token_data.bearer_tokens = [];
        serverData.token_data.session_tokens = [];
        serverData.session_data.is_logged_in = false;
        serverData.session_data.session_id = null;
        serverData.session_data.login_timestamp = null;
        serverData.session_data.token_validated = false;

        localStorage.removeItem('ivac_session');

        // Clear all cookies
        const cookies = getAllCookies();
        Object.keys(cookies).forEach(cookieName => {
            document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
        });

        console.log('[SESSION] Session completely cleared');
    }

    function updateSessionActivity() {
        serverData.session_data.last_activity = Date.now();
        saveSession();
    }

    // ==================== DYNAMIC IP DETECTION ====================
    async function detectClientIP() {
        if (serverData.ip_checked && serverData.client_ip) {
            return serverData.client_ip;
        }

        console.log('[IP] Detecting client IP address...');

        const ipDetectionMethods = [
            async () => {
                try {
                    const response = await fetch("https://payment.ivacbd.com/api/get-ip", {
                        method: "GET",
                        headers: { "accept": "*/*" },
                        credentials: "include"
                    });
                    if (response.ok) {
                        const data = await response.json();
                        if (data.ip && data.ip !== '::1') {
                            return data.ip;
                        }
                    }
                } catch (error) {
                    console.warn('[IP] IVAC IP detection failed:', error);
                }
                return null;
            },
            async () => {
                try {
                    const response = await fetch("https://api.ipify.org?format=json", {
                        method: "GET",
                        headers: { "accept": "application/json" }
                    });
                    if (response.ok) {
                        const data = await response.json();
                        return data.ip;
                    }
                } catch (error) {
                    console.warn('[IP] ipify detection failed:', error);
                }
                return null;
            },
            async () => {
                try {
                    const response = await fetch("https://api64.ipify.org?format=json");
                    if (response.ok) {
                        const data = await response.json();
                        return data.ip;
                    }
                } catch (error) {
                    console.warn('[IP] ipify64 detection failed:', error);
                }
                return null;
            }
        ];

        for (const method of ipDetectionMethods) {
            try {
                const ip = await method();
                if (ip && isValidIP(ip)) {
                    serverData.client_ip = ip;
                    serverData.ip_checked = true;
                    updateTokenDisplay();
                    console.log(`[IP] Client IP detected: ${ip}`);
                    return ip;
                }
            } catch (error) {
                console.warn('[IP] IP detection method failed:', error);
            }
        }

        // Fallback IP
        const fallbackIP = "119.148.60.137";
        serverData.client_ip = fallbackIP;
        serverData.ip_checked = true;
        updateTokenDisplay();
        console.warn(`[IP] Using fallback IP: ${fallbackIP}`);
        return fallbackIP;
    }

    function isValidIP(ip) {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipv4Regex.test(ip)) return false;
        const parts = ip.split('.');
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        });
    }

    // ==================== ENHANCED FETCH WITH BETTER TEXT PARSING ====================
    async function doFetch(url, options = {}) {
        if (checkRateLimit()) {
            const error = new Error('Rate limited');
            console.error('[FETCH] Rate limited:', url);
            return { ok: false, error: error, status: 429 };
        }

        await detectClientIP();

        const controller = new AbortController();
        activeRequests.add(controller);

        // Enhanced headers with token management
        const defaultHeaders = {
            'accept': 'application/json, text/x-component',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'priority': 'u=1, i',
            'sec-ch-ua': '"Chromium";v="142", "Google Chrome";v="142", "Not=A?Brand";v="99"',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'x-requested-with': 'XMLHttpRequest'
        };

        // Add authorization tokens dynamically
        if (serverData.access_token) {
            defaultHeaders['Authorization'] = `Bearer ${serverData.access_token}`;
        } else {
            // Try to use any available token
            const availableTokens = serverData.token_data.access_tokens;
            if (availableTokens.length > 0) {
                serverData.access_token = availableTokens[0].value;
                defaultHeaders['Authorization'] = `Bearer ${serverData.access_token}`;
                console.log('[FETCH] Using discovered access token');
            }
        }

        options.headers = { ...defaultHeaders, ...options.headers };
        options.signal = controller.signal;
        options.mode = 'cors';
        options.credentials = 'include';
        options.referrer = 'https://payment.ivacbd.com/application';

        // Log request details
        console.group(`🚀 API Request: ${options.method || 'GET'} ${url}`);
        console.log('📤 Request Headers:', options.headers);
        console.log('📤 Request Body:', options.body);
        console.groupEnd();

        try {
            const response = await fetch(url, options);
            let json = null;
            let responseText = null;

            try {
                // First get the raw text response
                responseText = await response.text();
                console.log('[FETCH] Raw response text:', responseText);
                
                // Try to parse as JSON first
                if (responseText) {
                    try {
                        json = JSON.parse(responseText);
                        console.log('[FETCH] Successfully parsed as single JSON:', json);
                    } catch (e) {
                        // If single JSON parsing fails, try to parse as multiple JSON objects
                        console.log('[FETCH] Single JSON parse failed, trying text parsing...');
                        const parsedText = parseTextResponse(responseText);
                        if (parsedText) {
                            json = parsedText;
                            console.log('[FETCH] Successfully parsed text response:', json);
                        } else {
                            // If text parsing also fails, store the raw text
                            json = { rawText: responseText };
                            console.log('[FETCH] Storing raw text response');
                        }
                    }
                }
            } catch (e) {
                console.warn(`[FETCH] Response processing failed for ${url}:`, e);
                // If JSON parsing fails, but we have text, use that
                if (responseText) {
                    json = { rawText: responseText };
                }
            }

            // Extract and update tokens from response
            updateTokensFromResponse(response, json);

            activeRequests.delete(controller);
            updateSessionActivity();

            if (response.status === 429) {
                const retryAfter = response.headers.get('Retry-After') || '12';
                const seconds = parseInt(retryAfter);
                startRateLimitTimer(seconds);
            }

            const result = {
                ok: response.ok,
                status: response.status,
                statusText: response.statusText,
                json: json,
                data: json, // Add data property for compatibility
                headers: response.headers,
                text: responseText, // Include raw text for debugging
                url: url,
                method: options.method || 'GET'
            };

            console.group(`📨 API Response: ${options.method || 'GET'} ${url}`);
            console.log('🔹 Response Status:', response.status, response.statusText);
            console.log('🔹 Response Headers:', Object.fromEntries(response.headers.entries()));
            console.log('🔹 Response JSON:', json);
            console.log('🔹 Response Text:', responseText);
            console.groupEnd();

            return result;
        } catch (e) {
            activeRequests.delete(controller);
            console.error(`[FETCH] Network error for ${url}:`, e);
            return {
                ok: false,
                error: e.name === 'AbortError' ? new Error('Request cancelled') : e,
                url: url,
                method: options.method || 'GET'
            };
        }
    }

    // ==================== FIXED DATA SUBMIT FUNCTIONS ====================
    async function btnAppAction() {
        if (checkRateLimit()) return false;
        if (!config.highcom || !config.ivac_id || !config.visa_type || !config.webid) {
            setStatus('Missing configuration. Please check Files Configuration.', true);
            return false;
        }
        try {
            setStatus('🔄 Solving captcha for application...');
            const captchaToken = await solveTurnstileCaptcha('application');

            setStatus('📝 Submitting application information...');
            const payload = getApplicationPayload(captchaToken);
            
            console.log('[APPLICATION] Sending payload:', payload);
            
            const response = await doFetch('https://payment.ivacbd.com/application', {
                method: 'POST',
                headers: {
                    'content-type': 'text/plain;charset=UTF-8',
                    'next-action': '70377b6e06ac0b9b4ffe55dbae6a64786750c62482'
                },
                body: JSON.stringify([payload, false, serverData.client_ip])
            });

            const parsed = parseApiResponse(response);
            
            // Use the enhanced status function
            setDetailedStatus('Application Submission', response, parsed);
            
            if (parsed.success) {
                serverData.application_payload = payload;
                saveAppData();
                showResponsePreview('Application Response:', parsed.fullResponse);
                return true;
            } else {
                return false;
            }
        } catch (e) {
            setStatus(`❌ Application submission failed: ${e.message}`, true);
            return false;
        }
    }

    // Enhanced Personal Info Submission
    async function btnPersonalAction() {
        if (checkRateLimit()) return false;
        if (!config.fullname || !config.emailname || !config.mobileNumber || !config.webid) {
            setStatus('Missing personal info. Please check Files Configuration.', true);
            return false;
        }
        try {
            setStatus('👤 Submitting personal information...');
            const payload = getPersonalInfoPayload();
            
            console.log('[PERSONAL] Sending payload:', payload);
            
            const response = await doFetch('https://payment.ivacbd.com/application', {
                method: 'POST',
                headers: {
                    'content-type': 'text/plain;charset=UTF-8',
                    'next-action': '706597cd5e9803020d2c67c2d54323975b19fff992'
                },
                body: JSON.stringify([payload, false, serverData.client_ip])
            });

            const parsed = parseApiResponse(response);
            
            // Use enhanced status
            setDetailedStatus('Personal Information', response, parsed);
            
            if (parsed.success) {
                serverData.personal_payload = payload;
                saveAppData();
                showResponsePreview('Personal Info Response:', parsed.fullResponse);
                return true;
            } else {
                return false;
            }
        } catch (error) {
            setStatus(`❌ Personal info submission failed: ${error.message}`, true);
            return false;
        }
    }

    // Enhanced Overview Submission
    async function btnOverviewAction() {
        if (checkRateLimit()) return false;
        try {
            setStatus('📊 Submitting booking overview...');
            const response = await doFetch('https://payment.ivacbd.com/application', {
                method: 'POST',
                headers: {
                    'content-type': 'text/plain;charset=UTF-8',
                    'next-action': '609be894c11698a9fdc88b9c6f9fa821916c7fb66d'
                },
                body: JSON.stringify(["en", serverData.client_ip])
            });

            const parsed = parseApiResponse(response);
            
            // Use enhanced status
            setDetailedStatus('Booking Overview', response, parsed);
            
            if (parsed.success) {
                serverData.overview_response = parsed.fullResponse;
                saveAppData();
                showResponsePreview('Overview Response:', parsed.fullResponse);
                return true;
            } else {
                return false;
            }
        } catch (error) {
            setStatus(`❌ Overview submission failed: ${error.message}`, true);
            return false;
        }
    }

    // Enhanced OTP Sending
    async function sendOTP(isResend = false) {
        if (checkRateLimit()) return false;

        setStatus(isResend ? '🔄 Resending OTP...' : '📤 Sending OTP...');
        const response = await doFetch('https://payment.ivacbd.com/application', {
            method: 'POST',
            headers: {
                'accept': 'text/x-component',
                'content-type': 'text/plain;charset=UTF-8',
                'next-action': '60f17fb803892fb0b32edd6a8970820aaeccaea2a1',
                'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22(root)%22%2C%7B%22children%22%3A%5B%22application%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
            },
            body: JSON.stringify([isResend ? 1 : 0, serverData.client_ip])
        });

        const parsed = parseApiResponse(response);
        
        // Use enhanced status
        setDetailedStatus(isResend ? 'Resend OTP' : 'Send OTP', response, parsed);
        
        if (parsed.success) {
            serverData.appointment_date = parsed.data?.appointment_date || serverData.appointment_date;
            serverData.hash_param = parsed.data?.hash_param || serverData.hash_param;
            showResponsePreview('Send OTP Response:', parsed.fullResponse);
            return true;
        } else {
            return false;
        }
    }

    // Enhanced OTP Verification
    async function btnVerifyOtpAction() {
        if (checkRateLimit()) return false;

        const payOtpInput = document.getElementById('pay-otp-input');
        const otp = payOtpInput ? payOtpInput.value.trim() : '';
        if (!otp) {
            setStatus('❌ Enter OTP', true);
            return false;
        }

        setStatus('🔍 Verifying OTP...');
        const response = await doFetch('https://payment.ivacbd.com/application', {
            method: 'POST',
            headers: {
                'accept': 'text/x-component',
                'content-type': 'text/plain;charset=UTF-8',
                'next-action': '607dd046ce4104a30dbcdae5ed02bdae7160e39745',
                'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22(root)%22%2C%7B%22children%22%3A%5B%22application%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
            },
            body: JSON.stringify([otp, serverData.client_ip])
        });

        const parsed = parseApiResponse(response);
        
        // Use enhanced status
        setDetailedStatus('Verify OTP', response, parsed);
        
        if (parsed.success) {
            serverData.appointment_date = parsed.data?.slot_dates?.[0] || serverData.appointment_date;
            serverData.hash_param = parsed.data?.hash_param || serverData.hash_param;
            const appointmentInput = document.getElementById('appointment-input');
            if (appointmentInput) {
                appointmentInput.value = serverData.appointment_date;
            }
            config.appiDate = serverData.appointment_date;
            saveConfig();
            saveAppData();
            return true;
        } else {
            return false;
        }
    }

    async function btnSlotLoadAction() {
        if (checkRateLimit()) return false;

        const appointmentInput = document.getElementById('appointment-input');
        const date = appointmentInput ? appointmentInput.value : serverData.appointment_date;
        setStatus(`⏰ Loading slots for ${date}...`);
        const response = await doFetch('https://payment.ivacbd.com/application', {
            method: 'POST',
            headers: {
                'accept': 'text/x-component',
                'content-type': 'text/plain;charset=UTF-8',
                'next-action': '60fd1e878d947ecff768e3fa5d1049d5bf42b6f548',
                'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22(root)%22%2C%7B%22children%22%3A%5B%22application%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
            },
            body: JSON.stringify([date, serverData.client_ip])
        });

        const parsed = parseApiResponse(response);
        
        // Use enhanced status
        setDetailedStatus('Load Slots', response, parsed);
        
        if (parsed.success) {
            serverData.appointment_date = parsed.data?.appointment_date || serverData.appointment_date;
            if (appointmentInput) {
                appointmentInput.value = serverData.appointment_date;
            }
            serverData.slot_times = parsed.data?.slot_times || [];
            populateSlotSelect(serverData.slot_times);
            saveAppData();
            return true;
        } else {
            return false;
        }
    }

    // ==================== ENHANCED CAPTCHA GENERATION ====================
    async function generateCaptcha() {
        setStatus('🔄 Generating captcha...');
        try {
            const response = await doFetch('https://payment.ivacbd.com/application', {
                method: 'POST',
                headers: {
                    'accept': 'text/x-component',
                    'content-type': 'text/plain;charset=UTF-8',
                    'next-action': '70648dcd61dd835363065814f031d26034cc029dfa',
                    'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22(root)%22%2C%7B%22children%22%3A%5B%22application%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
                },
                body: JSON.stringify(["$undefined", "$undefined", serverData.client_ip])
            });

            console.log('[CAPTCHA] Full response received');
            debugCaptchaResponse(response);

            const captchaParsed = parseCaptchaResponse(response);
            
            if (captchaParsed.success) {
                serverData.captcha_data.captcha_id = captchaParsed.captcha_id;
                serverData.captcha_data.is_verified = false;
                serverData.captcha_data.captcha_solution = null;
                serverData.captcha_data.generated_at = new Date().toISOString();

                console.log('[CAPTCHA] Successfully parsed captcha ID:', captchaParsed.captcha_id);

                // If we don't have the image data, fetch it separately
                let imageData = captchaParsed.captcha_image;
                if (!imageData) {
                    console.log('[CAPTCHA] No image in initial response, fetching image separately...');
                    setStatus('🔄 Fetching CAPTCHA image...');
                    
                    try {
                        imageData = await fetchCaptchaImage(captchaParsed.captcha_id);
                        console.log('[CAPTCHA] Successfully fetched image data');
                    } catch (imageError) {
                        console.error('[CAPTCHA] Failed to fetch image:', imageError);
                        // Continue anyway, we'll try to display with what we have
                    }
                }

                serverData.captcha_data.captcha_image = imageData;

                // Display the captcha
                const displaySuccess = await displayCaptchaImage(
                    serverData.captcha_data.captcha_image, 
                    serverData.captcha_data.captcha_id
                );

                if (displaySuccess) {
                    setStatus(`✅ ${captchaParsed.message}`);
                    showResponsePreview('Generate Captcha Response:', response.json);
                    return true;
                } else {
                    // If display fails but we have captcha_id, show success message anyway
                    setStatus(`✅ ${captchaParsed.message} (ID: ${captchaParsed.captcha_id})`);
                    showResponsePreview('Generate Captcha Response:', response.json);
                    return true;
                }
            } else {
                console.error('[CAPTCHA] Parse failed:', captchaParsed);
                throw new Error(captchaParsed.message || 'Failed to generate captcha');
            }
        } catch (e) {
            const errorMsg = `Error generating captcha: ${e.message}`;
            setStatus(`❌ ${errorMsg}`, true);

            const captchaStatus = document.getElementById('payment-captcha-status');
            if (captchaStatus) {
                captchaStatus.textContent = `❌ ${errorMsg}`;
                captchaStatus.style.color = '#ef4444';
            }
            return false;
        }
    }

    // Enhanced Captcha Verification
    async function verifyCaptcha() {
        const captchaInput = document.getElementById('payment-captcha-input');
        if (!captchaInput) {
            setStatus('❌ Captcha input not found', true);
            return false;
        }

        const solution = captchaInput.value.trim();
        if (!solution) {
            setStatus('❌ Please enter captcha text', true);
            return false;
        }

        if (!serverData.captcha_data.captcha_id) {
            setStatus('❌ No captcha ID available. Generate captcha first.', true);
            return false;
        }

        setStatus('🔍 Verifying captcha...');
        try {
            const response = await doFetch('https://payment.ivacbd.com/application', {
                method: 'POST',
                headers: {
                    'accept': 'text/x-component',
                    'content-type': 'text/plain;charset=UTF-8',
                    'next-action': '70648dcd61dd835363065814f031d26034cc029dfa',
                    'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22(root)%22%2C%7B%22children%22%3A%5B%22application%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
                },
                body: JSON.stringify([serverData.captcha_data.captcha_id, solution, serverData.client_ip])
            });

            const parsed = parseApiResponse(response);
            
            // Use enhanced status
            setDetailedStatus('Verify Captcha', response, parsed);
            
            if (parsed.success) {
                serverData.captcha_data.captcha_solution = solution;
                serverData.captcha_data.is_verified = true;
                serverData.hash_param = serverData.captcha_data.captcha_id;

                // Hide captcha image after successful verification
                const captchaImg = document.getElementById('payment-captcha-image');
                if (captchaImg) {
                    captchaImg.style.display = 'none';
                }

                // Clear the input field
                captchaInput.value = '';

                // Update status
                const captchaStatus = document.getElementById('payment-captcha-status');
                if (captchaStatus) {
                    captchaStatus.textContent = `✅ ${parsed.message}`;
                    captchaStatus.style.color = '#10b981';
                }

                showResponsePreview('Verify Captcha Response:', parsed.fullResponse);
                return true;
            } else {
                serverData.captcha_data.is_verified = false;
                const captchaStatus = document.getElementById('payment-captcha-status');
                if (captchaStatus) {
                    captchaStatus.textContent = `❌ ${parsed.message}`;
                    captchaStatus.style.color = '#ef4444';
                }
                return false;
            }
        } catch (e) {
            const errorMsg = `Error verifying captcha: ${e.message}`;
            setStatus(`❌ ${errorMsg}`, true);

            const captchaStatus = document.getElementById('payment-captcha-status');
            if (captchaStatus) {
                captchaStatus.textContent = `❌ ${errorMsg}`;
                captchaStatus.style.color = '#ef4444';
            }
            return false;
        }
    }

    // Enhanced Captcha Display Function
    async function displayCaptchaImage(imageData, captchaId) {
        const captchaImg = document.getElementById('payment-captcha-image');
        const captchaStatus = document.getElementById('payment-captcha-status');
        const captchaIdDisplay = document.getElementById('captcha-id-display');
        const captchaInput = document.getElementById('payment-captcha-input');

        if (!captchaImg) {
            console.error('[CAPTCHA] Image element not found');
            return false;
        }

        console.log('[CAPTCHA] Displaying image, data length:', imageData ? imageData.length : 'No data');
        console.log('[CAPTCHA] Image data preview:', imageData ? imageData.substring(0, 150) : 'No data');

        try {
            // If no image data but we have captcha ID, create a placeholder
            if (!imageData && captchaId) {
                console.log('[CAPTCHA] No image data, creating placeholder');
                
                // Create a placeholder message
                const placeholderText = `CAPTCHA ID: ${captchaId}\nImage not available\nPlease refresh or try again`;
                
                // Create a canvas with the placeholder text
                const canvas = document.createElement('canvas');
                canvas.width = 300;
                canvas.height = 100;
                const ctx = canvas.getContext('2d');
                
                // Draw background
                ctx.fillStyle = '#f0f0f0';
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                
                // Draw border
                ctx.strokeStyle = '#4facfe';
                ctx.lineWidth = 2;
                ctx.strokeRect(0, 0, canvas.width, canvas.height);
                
                // Draw text
                ctx.fillStyle = '#333333';
                ctx.font = '14px Arial';
                ctx.textAlign = 'center';
                const lines = placeholderText.split('\n');
                lines.forEach((line, index) => {
                    ctx.fillText(line, canvas.width / 2, 30 + (index * 20));
                });
                
                // Set the canvas as image source
                captchaImg.src = canvas.toDataURL();
                captchaImg.style.display = 'block';
                captchaImg.alt = 'CAPTCHA Placeholder';
                
                // Update status
                if (captchaStatus) {
                    captchaStatus.textContent = '⚠️ CAPTCHA generated but image not available. Please refresh.';
                    captchaStatus.style.color = '#fbbf24';
                }
            } 
            // If we have image data, try to display it
            else if (imageData) {
                let cleanImageData = imageData;
                
                // Clean the image data
                if (!cleanImageData.startsWith('data:image/png;base64,')) {
                    console.log('[CAPTCHA] Cleaning image data...');
                    
                    // Find the actual base64 data start
                    const base64Start = cleanImageData.indexOf('data:image/png;base64,');
                    if (base64Start !== -1) {
                        cleanImageData = cleanImageData.substring(base64Start);
                    } else if (cleanImageData.includes('base64,')) {
                        const base64Part = cleanImageData.split('base64,')[1];
                        cleanImageData = `data:image/png;base64,${base64Part}`;
                    } else {
                        cleanImageData = `data:image/png;base64,${cleanImageData}`;
                    }
                }

                // Test the image data first
                const testImg = new Image();
                await new Promise((resolve, reject) => {
                    testImg.onload = () => {
                        console.log('[CAPTCHA] Test image loaded successfully');
                        resolve(true);
                    };
                    testImg.onerror = (e) => {
                        console.error('[CAPTCHA] Test image failed:', e);
                        reject(new Error('Invalid base64 image data'));
                    };
                    testImg.src = cleanImageData;
                    
                    setTimeout(() => {
                        if (!testImg.complete) {
                            reject(new Error('Test image loading timeout'));
                        }
                    }, 3000);
                });

                // Now set the actual image
                captchaImg.src = cleanImageData;
                captchaImg.style.display = 'block';
                captchaImg.alt = 'Payment CAPTCHA';

                // Wait for the actual image to load
                await new Promise((resolve, reject) => {
                    let imageLoaded = false;

                    captchaImg.onload = () => {
                        imageLoaded = true;
                        console.log('[CAPTCHA] Actual image loaded successfully');
                        console.log('[CAPTCHA] Image dimensions:', captchaImg.naturalWidth, 'x', captchaImg.naturalHeight);
                        resolve(true);
                    };

                    captchaImg.onerror = (e) => {
                        console.error('[CAPTCHA] Actual image failed to load:', e);
                        reject(new Error('Failed to load CAPTCHA image'));
                    };

                    setTimeout(() => {
                        if (!imageLoaded) {
                            if (captchaImg.naturalWidth > 0 && captchaImg.naturalHeight > 0) {
                                resolve(true);
                            } else {
                                reject(new Error('Image loading timeout'));
                            }
                        }
                    }, 5000);
                });

                // Update status for successful load
                if (captchaStatus) {
                    captchaStatus.textContent = '✅ CAPTCHA loaded. Please enter the text above.';
                    captchaStatus.style.color = '#10b981';
                }
            }

            // Update common UI elements
            if (captchaIdDisplay) {
                captchaIdDisplay.textContent = `Captcha ID: ${captchaId}`;
                captchaIdDisplay.style.display = 'block';
            }

            if (captchaInput) {
                captchaInput.value = '';
                captchaInput.focus();
            }

            console.log('[CAPTCHA] UI updated successfully');
            return true;

        } catch (error) {
            console.error('[CAPTCHA] Display error:', error);

            if (captchaStatus) {
                captchaStatus.textContent = `❌ ${error.message}`;
                captchaStatus.style.color = '#ef4444';
            }

            // Create a fallback placeholder
            try {
                const canvas = document.createElement('canvas');
                canvas.width = 300;
                canvas.height = 100;
                const ctx = canvas.getContext('2d');
                ctx.fillStyle = '#ffebee';
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                ctx.fillStyle = '#d32f2f';
                ctx.font = '14px Arial';
                ctx.textAlign = 'center';
                ctx.fillText('CAPTCHA Load Failed', canvas.width / 2, 40);
                ctx.fillText('Please try again', canvas.width / 2, 65);
                
                captchaImg.src = canvas.toDataURL();
                captchaImg.style.display = 'block';
                return true;
            } catch (fallbackError) {
                console.error('[CAPTCHA] All display methods failed:', fallbackError);
                return false;
            }
        }
    }

    // RELOAD CAPTCHA FUNCTION
    async function reloadCaptcha() {
        console.log('[CAPTCHA] Reloading captcha...');

        // Reset current captcha UI
        resetCaptchaUI();

        // Small delay to ensure UI is reset
        await new Promise(resolve => setTimeout(resolve, 300));

        // Generate new captcha
        const result = await generateCaptcha();
        return result;
    }

    function resetCaptchaUI() {
        console.log('[CAPTCHA] Resetting UI');

        const captchaImg = document.getElementById('payment-captcha-image');
        if (captchaImg) {
            captchaImg.style.display = 'none';
            captchaImg.src = '';
            captchaImg.onload = null;
            captchaImg.onerror = null;
        }

        const captchaInput = document.getElementById('payment-captcha-input');
        if (captchaInput) {
            captchaInput.value = '';
        }

        const captchaIdDisplay = document.getElementById('captcha-id-display');
        if (captchaIdDisplay) {
            captchaIdDisplay.style.display = 'none';
            captchaIdDisplay.textContent = 'Captcha ID: Not generated';
        }

        const captchaStatus = document.getElementById('payment-captcha-status');
        if (captchaStatus) {
            captchaStatus.textContent = 'Captcha not generated';
            captchaStatus.style.color = '';
        }

        // Reset server data
        serverData.captcha_data = {
            captcha_id: null,
            captcha_image: null,
            captcha_solution: null,
            is_verified: false,
            generated_at: null
        };
    }

    // DEBUG FUNCTION - Add this to help troubleshoot
    function debugCaptchaResponse(response) {
        console.group('[CAPTCHA DEBUG]');
        console.log('Full response:', response);
        
        if (response.json) {
            console.log('Response keys:', Object.keys(response.json));
            
            Object.keys(response.json).forEach(key => {
                const value = response.json[key];
                console.log(`Key ${key}:`, typeof value === 'string' ? 
                    value.substring(0, 200) + (value.length > 200 ? '...' : '') : 
                    value);
            });
        }
        console.groupEnd();
    }

    // Enhanced Pay Now Function
    async function btnPayNowAction() {
        if (checkRateLimit()) return false;

        if (!serverData.appointment_date || !serverData.appointment_time_final) {
            setStatus('❌ Missing appointment date or time. Please load slots.', true);
            return false;
        }

        const btnPayNow = document.getElementById('btn-pay-now');
        const originalText = btnPayNow.textContent;
        btnPayNow.textContent = '⏳ Processing...';
        btnPayNow.disabled = true;

        try {
            // Create form data for multipart request
            const formData = new FormData();
            formData.append('1_appointment_date', serverData.appointment_date);
            formData.append('1_appointment_time', serverData.appointment_time_final);
            formData.append('1_k5t0g8_token_y4v9f6', serverData.captcha_data.captcha_id || '');
            formData.append('1_selected_payment[name]', serverData.selected_payment.name);
            formData.append('1_selected_payment[slug]', serverData.selected_payment.slug);
            formData.append('1_selected_payment[link]', serverData.selected_payment.link);
            formData.append('0', JSON.stringify(["$K1", serverData.client_ip]));

            const response = await doFetch('https://payment.ivacbd.com/application', {
                method: 'POST',
                headers: {
                    'accept': 'text/x-component',
                    'content-type': 'multipart/form-data; boundary=----WebKitFormBoundaryEBVSPiMFvmMYRCdL',
                    'next-action': '60e3bf50cd36841322301d5ae4f1f1df55d0e26cd2',
                    'next-router-state-tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22(root)%22%2C%7B%22children%22%3A%5B%22application%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
                },
                body: formData
            });

            const parsed = parseApiResponse(response);
            
            // Use enhanced status
            setDetailedStatus('Pay Now', response, parsed);
            
            if (parsed.success) {
                serverData.payment_link = parsed.data?.url;

                // Show payment URL
                if (serverData.payment_link) {
                    showUrlPopup(serverData.payment_link);
                }

                showResponsePreview('Pay Now Response:', parsed.fullResponse);
                return true;
            }
            return false;
        } catch (e) {
            setStatus(`❌ Payment error: ${e.message}`, true);
            return false;
        } finally {
            btnPayNow.textContent = originalText;
            btnPayNow.disabled = false;
        }
    }

    // ==================== SLOT MANAGEMENT ====================
    function populateSlotSelect(slots) {
        const slotSelect = document.getElementById('payment-slot-select');
        const slotInfo = document.getElementById('slot-info');
        if (!slotSelect) return;

        slotSelect.innerHTML = '';

        if (slots && slots.length > 0) {
            let availableSlots = 0;
            let defaultSelected = false;

            slots.forEach(slot => {
                const option = document.createElement('option');
                const timeDisplay = slot.time_display || slot.slot || `${slot.from} - ${slot.to}`;
                option.value = timeDisplay;
                option.textContent = timeDisplay + (slot.available !== false ? ' ✓ Available' : ' ❌ Full');

                if (slot.available === false) {
                    option.disabled = true;
                } else {
                    availableSlots++;

                    // Auto-select based on configuration
                    if (config.autoSelectFirstAvailable && !defaultSelected) {
                        option.selected = true;
                        serverData.appointment_time_final = option.value;
                        defaultSelected = true;
                    }

                    // Auto-select default time if configured
                    if (config.defaultTime && timeDisplay.includes(config.defaultTime) && !defaultSelected) {
                        option.selected = true;
                        serverData.appointment_time_final = option.value;
                        defaultSelected = true;
                    }
                }

                slotSelect.appendChild(option);
            });

            if (slotInfo) {
                const availableSlotList = slots.filter(slot => slot.available !== false)
                .map(slot => {
                    const time = slot.time_display || slot.slot || `${slot.from} - ${slot.to}`;
                    const seats = slot.availableSlot ? `(${slot.availableSlot} seats)` : '';
                    return `${time} ${seats}`;
                }).join(', ');

                slotInfo.innerHTML = `
                    <div class="slot-summary">
                        <strong>${availableSlots} Available Slots</strong>
                        ${config.autoSelectFirstAvailable ? '<span class="auto-select-badge">Auto-Select Enabled</span>' : ''}
                    </div>
                    <div class="slot-times">${availableSlotList || 'No slots available'}</div>
                `;

                if (availableSlots > 0) {
                    slotInfo.className = 'slot-info available';
                } else {
                    slotInfo.className = 'slot-info unavailable';
                }
            }
        } else {
            const option = document.createElement('option');
            option.textContent = 'No slots available';
            option.disabled = true;
            slotSelect.appendChild(option);

            if (slotInfo) {
                slotInfo.innerHTML = '<div class="slot-summary"><strong>No slots available</strong></div>';
                slotInfo.className = 'slot-info unavailable';
            }
        }

        saveAppData();
    }

    function injectTimeSlots() {
        setStatus('🔄 Injecting time slots...');

        let timeDropdown = document.getElementById('appointment_time');
        if (!timeDropdown) {
            timeDropdown = document.getElementById('ivac-time-dropdown');
        }

        // Also check the payment tab dropdown
        if (!timeDropdown) {
            const slotSelect = document.getElementById('payment-slot-select');
            if (slotSelect) {
                timeDropdown = slotSelect;
            }
        }

        if (timeDropdown) {
            const timeSlots = [
                "09:00 - 09:59"
            ];

            timeDropdown.innerHTML = `
                <option value="">Select an Appointment Time</option>
                ${timeSlots.map(time => `<option value="${time}">${time}</option>`).join('')}
            `;
            timeDropdown.style.display = '';
            timeDropdown.classList.remove('d-none');

            // Auto-select default time if configured
            if (config.defaultTime) {
                timeDropdown.value = config.defaultTime;
                serverData.appointment_time_final = config.defaultTime;
            }

            console.log("Time slots injected successfully");
            setStatus('✅ Time slots injected successfully');

            // Update slot info display
            const slotInfo = document.getElementById('slot-info');
            if (slotInfo) {
                slotInfo.innerHTML = `
                    <div class="slot-summary">
                        <strong>${timeSlots.length} Time Slots Available</strong>
                        <span class="auto-select-badge">Manual Injection</span>
                    </div>
                    <div class="slot-times">${timeSlots.join(', ')}</div>
                `;
                slotInfo.className = 'slot-info available';
            }
        } else {
            console.error("Time dropdown element not found");
            setStatus('❌ Time dropdown not found', true);
        }
    }

    function updateDatePicker(dates = []) {
        setStatus('🔄 Updating date picker...');

        const dateInput = document.getElementById("ivac-date-input");
        const appointmentInput = document.getElementById("appointment-date-input") || document.querySelector('input[type="date"]');

        let targetInput = dateInput;
        if (!targetInput && appointmentInput) {
            targetInput = appointmentInput;
        }

        if (!targetInput) {
            console.warn("Date input not found");
            setStatus('❌ Date input not found', true);
            return;
        }

        // Set default date from config or fallback
        const defaultDate = config.appiDate || "";
        targetInput.value = defaultDate;
        serverData.appointment_date = defaultDate;
        window.selectedDate = defaultDate;

        if (dates.length > 0) {
            const sortedDates = dates.sort();
            targetInput.min = sortedDates[0];
            targetInput.max = sortedDates[sortedDates.length - 1];
        }

        // Auto-trigger slot load on date change
        targetInput.onchange = async (e) => {
            window.selectedDate = e.target.value;
            serverData.appointment_date = e.target.value;
            config.appiDate = e.target.value;
            saveConfig();

            setStatus(`📅 Date changed to: ${e.target.value}`);

            const timeDropdown = document.getElementById("ivac-time-dropdown") || document.getElementById("payment-slot-select");
            if (timeDropdown) {
                timeDropdown.innerHTML = '<option value="">Select Time</option>';
            }

            // Auto-load slots if on payment tab
            if (currentTab === 'payment') {
                setTimeout(() => {
                    btnSlotLoadAction();
                }, 500);
            }
        };

        console.log("Date picker updated with default:", defaultDate);
        setStatus(`✅ Date set to ${defaultDate}`);
    }

    // ==================== RESPONSE PREVIEW FUNCTION ====================
    function showResponsePreview(title, responseData) {
        // Remove existing preview if any
        const existingPreview = document.getElementById('response-preview');
        if (existingPreview) existingPreview.remove();

        // Create preview container
        const preview = document.createElement('div');
        preview.id = 'response-preview';
        Object.assign(preview.style, {
            position: 'fixed',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            background: 'linear-gradient(135deg, #1e293b 0%, #334155 100%)',
            padding: '20px',
            borderRadius: '12px',
            border: '2px solid rgba(255,255,255,0.2)',
            boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
            zIndex: '10000003',
            width: '600px',
            maxWidth: '90vw',
            maxHeight: '80vh',
            overflow: 'auto',
            fontFamily: 'monospace, Arial, sans-serif',
            color: '#e2e8f0',
            fontSize: '12px'
        });

        // Format the response data for display
        let formattedResponse = JSON.stringify(responseData, null, 2);

        // If it's a captcha response with image data, truncate the image data for display
        if (responseData.data && responseData.data.captcha_image) {
            const truncatedResponse = JSON.parse(JSON.stringify(responseData));
            if (truncatedResponse.data.captcha_image) {
                truncatedResponse.data.captcha_image = truncatedResponse.data.captcha_image.substring(0, 100) + '... [TRUNCATED]';
            }
            formattedResponse = JSON.stringify(truncatedResponse, null, 2);
        }

        preview.innerHTML = `
            <div style="margin-bottom: 15px;">
                <h3 style="margin: 0 0 10px 0; color: #38bdf8; font-size: 16px; font-weight: 600;">${title}</h3>
                <div style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.1);">
                    <pre style="margin: 0; white-space: pre-wrap; word-wrap: break-word;">${formattedResponse}</pre>
                </div>
            </div>
            <button id="preview-close"
                style="width: 100%; padding: 10px; background: rgba(239,68,68,0.2);
                       color: #ef4444; border: 1px solid rgba(239,68,68,0.3);
                       border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;">
                Close Preview
            </button>
        `;

        document.body.appendChild(preview);

        // Close functionality
        preview.querySelector('#preview-close').onclick = function () {
            preview.remove();
        };

        // Close when clicking outside
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.7);
            z-index: 10000002;
        `;
        document.body.appendChild(overlay);

        overlay.onclick = function () {
            preview.remove();
            overlay.remove();
        };

        preview.querySelector('#preview-close').onclick = function () {
            preview.remove();
            overlay.remove();
        };
    }

    // ==================== PAYMENT POPUP FUNCTION ====================
    function showUrlPopup(url) {
        // Remove existing popups if any
        const existingOverlay = document.getElementById('tm-overlay');
        const existingPopup = document.getElementById('tm-popup');
        if (existingOverlay) existingOverlay.remove();
        if (existingPopup) existingPopup.remove();

        // Create overlay
        const overlay = document.createElement('div');
        overlay.id = 'tm-overlay';
        Object.assign(overlay.style, {
            position: 'fixed',
            top: '0',
            left: '0',
            right: '0',
            bottom: '0',
            background: 'rgba(0,0,0,0.8)',
            zIndex: '10000001',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            backdropFilter: 'blur(5px)'
        });

        // Create modern popup
        const popup = document.createElement('div');
        popup.id = 'tm-popup';
        Object.assign(popup.style, {
            position: 'fixed',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            background: 'linear-gradient(135deg, #1e3c72 0%, #2a5298 100%)',
            padding: '30px',
            borderRadius: '20px',
            border: '2px solid rgba(255,255,255,0.2)',
            boxShadow: '0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.1)',
            zIndex: '10000002',
            width: '450px',
            maxWidth: '90vw',
            fontFamily: 'Arial, sans-serif',
            textAlign: 'center',
            color: '#ffffff',
            backdropFilter: 'blur(10px)'
        });

        popup.innerHTML = `
            <div style="margin-bottom: 20px;">
                <div style="font-size: 24px; margin-bottom: 8px;">🎉</div>
                <h3 style="margin: 0 0 10px 0; color: #ffffff; font-size: 22px; font-weight: 700;">Payment URL Generated!</h3>
                <p style="margin-bottom: 20px; color: rgba(255,255,255,0.9); font-size: 14px; line-height: 1.4;">
                    Your payment link has been successfully generated. Click the buttons below to copy or open the link.
                </p>
            </div>
            <div style="position: relative; margin-bottom: 25px;">
                <input type="text" id="tm-url" value="${url}" readonly
                    style="width: 100%; padding: 15px; border: 2px solid rgba(255,255,255,0.3);
                           border-radius: 12px; background: rgba(255,255,255,0.1);
                           color: #ffffff; font-size: 14px; box-sizing: border-box;
                           backdropFilter: blur(10px);">
            </div>
            <div style="display: flex; gap: 12px; justify-content: center; margin-bottom: 20px;">
                <button id="tm-copy"
                    style="flex: 1; padding: 15px 20px; background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
                           color: #1a3c2e; border: none; border-radius: 12px; cursor: pointer;
                           font-weight: 700; font-size: 14px; transition: all 0.3s ease;
                           boxShadow: 0 8px 25px rgba(67, 233, 123, 0.3);">
                    📋 Copy Link
                </button>
                <button id="tm-open"
                    style="flex: 1; padding: 15px 20px; background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                           color: white; border: none; border-radius: 12px; cursor: pointer;
                           font-weight: 700; font-size: 14px; transition: all 0.3s ease;
                           boxShadow: 0 8px 25px rgba(79, 172, 254, 0.3);">
                    🔗 Open Link
                </button>
            </div>
            <div id="tm-feedback" style="color: #43e97b; font-weight: 700; font-size: 14px; margin: 15px 0; min-height: 20px;"></div>
            <button id="tm-close"
                style="width: 100%; padding: 12px 20px; background: rgba(255,255,255,0.2);
                       color: white; border: 2px solid rgba(255,255,255,0.3); border-radius: 10px;
                       cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.3s ease;
                       backdropFilter: blur(10px);">
                Close Panel
            </button>
        `;

        document.body.appendChild(overlay);
        document.body.appendChild(popup);

        // Add hover effects
        const copyBtn = document.getElementById('tm-copy');
        const openBtn = document.getElementById('tm-open');
        const closeBtn = document.getElementById('tm-close');

        // Hover effects for buttons
        [copyBtn, openBtn, closeBtn].forEach(btn => {
            btn.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-2px)';
                this.style.boxShadow = '0 12px 30px rgba(0,0,0,0.4)';
            });
            btn.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
                if (this.id === 'tm-copy') {
                    this.style.boxShadow = '0 8px 25px rgba(67, 233, 123, 0.3)';
                } else if (this.id === 'tm-open') {
                    this.style.boxShadow = '0 8px 25px rgba(79, 172, 254, 0.3)';
                } else {
                    this.style.boxShadow = 'none';
                }
            });
        });

        // Copy functionality
        copyBtn.onclick = function () {
            const input = document.getElementById('tm-url');
            input.select();
            input.setSelectionRange(0, 99999);

            try {
                const successful = document.execCommand('copy');
                const feedback = document.getElementById('tm-feedback');
                if (successful) {
                    feedback.textContent = '✅ Link copied to clipboard!';
                    feedback.style.color = '#43e97b';

                    // Visual feedback
                    const originalText = copyBtn.innerHTML;
                    copyBtn.innerHTML = '✅ Copied!';
                    copyBtn.style.background = 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)';

                    setTimeout(() => {
                        copyBtn.innerHTML = originalText;
                        copyBtn.style.background = 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)';
                    }, 2000);
                } else {
                    throw new Error('execCommand failed');
                }
            } catch (err) {
                // Fallback to modern clipboard API
                navigator.clipboard.writeText(url).then(() => {
                    const feedback = document.getElementById('tm-feedback');
                    feedback.textContent = '✅ Link copied to clipboard!';
                    feedback.style.color = '#43e97b';
                }).catch(() => {
                    const feedback = document.getElementById('tm-feedback');
                    feedback.textContent = '❌ Failed to copy. Please copy manually.';
                    feedback.style.color = '#ff6b6b';
                });
            }
        };

        // Open link functionality
        openBtn.onclick = function () {
            window.open(url, '_blank');
            const feedback = document.getElementById('tm-feedback');
            feedback.textContent = '🔗 Opening payment link...';
            feedback.style.color = '#4facfe';
        };

        // Close functionality
        closeBtn.onclick = function () {
            popup.remove();
            overlay.remove();
        };

        // Close when clicking outside
        overlay.onclick = function (e) {
            if (e.target === overlay) {
                popup.remove();
                overlay.remove();
            }
        };

        // Auto-select text in input
        setTimeout(() => {
            const input = document.getElementById('tm-url');
            input.select();
            input.style.borderColor = 'rgba(67, 233, 123, 0.5)';
        }, 100);
    }

    // ==================== UTILITY FUNCTIONS ====================
    function el(t, c) {
        const e = document.createElement(t);
        if (c) e.className = c;
        return e;
    }

    // Rate Limit Functions
    function startRateLimitTimer(seconds) {
        rateLimitSeconds = seconds;
        serverData.rateLimitReset = new Date(Date.now() + seconds * 1000);

        const rateLimitDisplay = document.getElementById('rate-limit-display');
        if (rateLimitDisplay) {
            rateLimitDisplay.textContent = `⏰ Rate Limited: ${seconds}s remaining`;
            rateLimitDisplay.style.display = 'block';
        }

        if (rateLimitTimer) {
            clearInterval(rateLimitTimer);
        }

        rateLimitTimer = setInterval(() => {
            rateLimitSeconds--;

            if (rateLimitDisplay) {
                rateLimitDisplay.textContent = `⏰ Rate Limited: ${rateLimitSeconds}s remaining`;
            }

            if (rateLimitSeconds <= 0) {
                clearInterval(rateLimitTimer);
                rateLimitTimer = null;
                serverData.rateLimitReset = null;

                if (rateLimitDisplay) {
                    rateLimitDisplay.style.display = 'none';
                }

                setStatus('✅ Rate limit period ended - requests can be made again');
            }
        }, 1000);
    }

    function checkRateLimit() {
        if (serverData.rateLimitReset && new Date() < serverData.rateLimitReset) {
            const secondsLeft = Math.ceil((serverData.rateLimitReset - new Date()) / 1000);
            setStatus(`⏰ Rate limited - please wait ${secondsLeft} seconds`, true);
            return true;
        }
        return false;
    }

    // Enhanced Family Member Functions with Auto Format
    function updateFamilyMembers() {
        const familyCount = parseInt(config.familyCount) || 0;
        const currentCount = config.family.length;

        if (familyCount > currentCount) {
            for (let i = currentCount; i < familyCount; i++) {
                config.family.push({
                    name: "",
                    webfile_no: "",
                    again_webfile_no: ""
                });
            }
        } else if (familyCount < currentCount) {
            config.family = config.family.slice(0, familyCount);
        }

        renderFamilyMembers();
        saveConfig();
    }

    function renderFamilyMembers() {
        const familyContainer = document.getElementById('family-members');
        if (!familyContainer) return;

        familyContainer.innerHTML = '';

        config.family.forEach((member, index) => {
            const memberDiv = el('div', 'family-member');
            memberDiv.innerHTML = `
                <div class="family-member-header">
                    <span class="family-member-title">👤 Family Member ${index + 1}</span>
                    <button class="ivac-btn small red remove-family-btn" data-index="${index}">🗑️</button>
                </div>
                <input class="ivac-input family-name" data-index="${index}" value="${member.name || ''}" placeholder="Full Name (as per passport)">
                <input class="ivac-input family-webfile" data-index="${index}" value="${member.webfile_no || ''}" placeholder="Webfile Number (e.g., BGDDV860D325)">
                <input class="ivac-input family-webfile-repeat" data-index="${index}" value="${member.again_webfile_no || member.webfile_no || ''}" placeholder="Confirm Webfile Number">
            `;
            familyContainer.appendChild(memberDiv);
        });

        // Add event listeners for family member inputs
        familyContainer.querySelectorAll('.family-name, .family-webfile, .family-webfile-repeat').forEach(input => {
            input.addEventListener('input', (e) => {
                const index = parseInt(e.target.dataset.index);
                const field = e.target.className.includes('family-name') ? 'name' :
                e.target.className.includes('family-webfile-repeat') ? 'again_webfile_no' : 'webfile_no';

                config.family[index][field] = e.target.value;

                // Auto-update repeat field if it's webfile number
                if (field === 'webfile_no') {
                    const repeatField = familyContainer.querySelector(`.family-webfile-repeat[data-index="${index}"]`);
                    if (repeatField && (!repeatField.value || repeatField.value === config.family[index].again_webfile_no)) {
                        repeatField.value = e.target.value;
                        config.family[index].again_webfile_no = e.target.value;
                    }
                }

                saveConfig();
            });
        });

        familyContainer.querySelectorAll('.remove-family-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = parseInt(e.target.dataset.index);
                config.family.splice(index, 1);
                config.familyCount = config.family.length.toString();
                renderFamilyMembers();
                updateFamilyCountSelect();
                saveConfig();
            });
        });
    }

    function updateFamilyCountSelect() {
        const familyCountSelect = document.getElementById('config-family-count');
        if (familyCountSelect) {
            familyCountSelect.value = config.familyCount;
        }
    }

    // Remember Me Functions
    function saveRememberMeData() {
        if (config.rememberMe) {
            try {
                const rememberData = {
                    mobileNumber: config.mobileNumber,
                    password: config.password,
                    emailname: config.emailname,
                    fullname: config.fullname,
                    webid: config.webid,
                    webid_repeat: config.webid_repeat,
                    highcom: config.highcom,
                    ivac_id: config.ivac_id,
                    visa_type: config.visa_type,
                    visit_purpose: config.visit_purpose,
                    family: config.family,
                    familyCount: config.familyCount,
                    defaultTime: config.defaultTime,
                    autoSelectFirstAvailable: config.autoSelectFirstAvailable,
                    appiDate: config.appiDate,
                    rememberMe: true,
                    savedAt: new Date().toISOString()
                };
                localStorage.setItem('ivac_remember_me', JSON.stringify(rememberData));
                setStatus('✅ Data saved with Remember Me');
            } catch (e) {
                console.error('[REMEMBER ME] Error saving data:', e);
                setStatus('❌ Error saving Remember Me data', true);
            }
        }
    }

    function loadRememberMeData() {
        try {
            const saved = localStorage.getItem('ivac_remember_me');
            if (saved) {
                const rememberData = JSON.parse(saved);

                if (rememberData.rememberMe) {
                    Object.keys(rememberData).forEach(key => {
                        if (config.hasOwnProperty(key)) {
                            config[key] = rememberData[key];
                        }
                    });
                    setStatus('✅ Remember Me data loaded successfully');
                    return true;
                }
            }
        } catch (e) {
            console.error('[REMEMBER ME] Error loading data:', e);
            setStatus('❌ Error loading Remember Me data', true);
        }
        return false;
    }

    function clearRememberMeData() {
        try {
            localStorage.removeItem('ivac_remember_me');
            config.rememberMe = true;
            setStatus('✅ Remember Me data cleared');
        } catch (e) {
            console.error('[REMEMBER ME] Error clearing data:', e);
            setStatus('❌ Error clearing Remember Me data', true);
        }
    }

    function toggleRememberMe(enable) {
        config.rememberMe = enable;
        if (enable) {
            saveRememberMeData();
        } else {
            clearRememberMeData();
        }
        updateRememberMeUI();
    }

    function updateRememberMeUI() {
        const rememberCheckbox = document.getElementById('remember-me-checkbox');
        const rememberStatus = document.getElementById('remember-me-status');
        const clearRememberBtn = document.getElementById('clear-remember-btn');

        if (rememberCheckbox) {
            rememberCheckbox.checked = config.rememberMe;
        }

        if (rememberStatus) {
            if (config.rememberMe) {
                rememberStatus.textContent = '✅ Remembering your data';
                rememberStatus.className = 'remember-status active';
            } else {
                rememberStatus.textContent = 'Remember Me is off';
                rememberStatus.className = 'remember-status inactive';
            }
        }

        if (clearRememberBtn) {
            clearRememberBtn.style.display = config.rememberMe ? 'block' : 'none';
        }
    }

    // Tab Management
    function switchTab(tabName) {
        const tabContents = document.querySelectorAll('.tab-content');
        tabContents.forEach(tab => tab.style.display = 'none');

        const tabs = document.querySelectorAll('.tab-btn');
        tabs.forEach(tab => tab.classList.remove('active'));

        const selectedTab = document.getElementById(`${tabName}-tab`);
        if (selectedTab) {
            selectedTab.style.display = 'block';
        }

        const selectedTabBtn = document.querySelector(`[data-tab="${tabName}"]`);
        if (selectedTabBtn) {
            selectedTabBtn.classList.add('active');
        }

        currentTab = tabName;

        if (tabName === 'data-submit') {
            document.getElementById('step-indicator').textContent = 'Data Submission';
            document.getElementById('step-indicator').style.background = 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)';
        } else if (tabName === 'payment') {
            document.getElementById('step-indicator').textContent = 'Payment Processing';
            document.getElementById('step-indicator').style.background = 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)';
        } else if (tabName === 'configuration') {
            document.getElementById('step-indicator').textContent = 'Configuration';
            document.getElementById('step-indicator').style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
        }
    }

    // Data Storage Functions
    function saveConfig() {
        try {
            localStorage.setItem('ivac_config', JSON.stringify(config));
            setStatus('✅ Configuration saved');

            if (config.rememberMe) {
                saveRememberMeData();
            }
        } catch (e) {
            setStatus(`❌ Error saving config: ${e.message}`, true);
        }
    }

    function loadConfig() {
        try {
            const s = localStorage.getItem('ivac_config');
            if (s) {
                config = JSON.parse(s);
                serverData.appointment_date = config.appiDate || "";
                setStatus('✅ Configuration loaded');
                return true;
            }
            setStatus('No saved configuration found. Please configure.');
            return false;
        } catch (e) {
            setStatus(`❌ Error loading config: ${e.message}`, true);
            return false;
        }
    }

    function saveAppData() {
        try {
            const a = {
                application_payload: serverData.application_payload,
                personal_payload: serverData.personal_payload,
                overview_response: serverData.overview_response
            };
            localStorage.setItem('ivac_app_data', JSON.stringify(a));
            setStatus('✅ Application data saved');
        } catch (e) {
            setStatus(`❌ Error saving app data: ${e.message}`, true);
        }
    }

    function loadAppData() {
        try {
            const s = localStorage.getItem('ivac_app_data');
            if (s) {
                const p = JSON.parse(s);
                serverData.application_payload = p.application_payload || null;
                serverData.personal_payload = p.personal_payload || null;
                serverData.overview_response = p.overview_response || null;
                setStatus('✅ Application data loaded');
                return true;
            }
            return false;
        } catch (e) {
            setStatus(`❌ Error loading app data: ${e.message}`, true);
            return false;
        }
    }

    function saveCookies() {
        try {
            const c = document.cookie.split(';').reduce((a, c) => {
                const [k, v] = c.trim().split('=');
                a[k] = v;
                return a;
            }, {});
            serverData.cookies = c;
            localStorage.setItem('ivac_cookies', JSON.stringify(c));
        } catch (e) {
            console.error('Error saving cookies:', e);
        }
    }

    function loadCookies() {
        try {
            const s = localStorage.getItem('ivac_cookies');
            if (s) {
                serverData.cookies = JSON.parse(s);
                Object.entries(serverData.cookies).forEach(([k, v]) => {
                    document.cookie = `${k}=${v}; path=/; max-age=86400`;
                });
                setStatus('✅ Cookies loaded');
                return true;
            }
            return false;
        } catch (e) {
            console.error('Error loading cookies:', e);
            return false;
        }
    }

    function exportConfig() {
        try {
            const e = {
                config,
                app_data: {
                    application_payload: serverData.application_payload,
                    personal_payload: serverData.personal_payload,
                    overview_response: serverData.overview_response
                },
                cookies: serverData.cookies
            };
            const j = JSON.stringify(e, null, 2);
            exportPopup.querySelector('#export-json').value = j;
            exportPopup.style.display = 'block';
            setStatus('✅ Configuration exported to popup');
        } catch (er) {
            setStatus(`❌ Error exporting config: ${er.message}`, true);
        }
    }

    function importConfig(c) {
        try {
            const p = JSON.parse(c);
            config = {
                ...config,
                ...p.config
            };
            serverData.appointment_date = config.appiDate || "";
            serverData.application_payload = p.app_data?.application_payload || null;
            serverData.personal_payload = p.app_data?.personal_payload || null;
            serverData.overview_response = p.app_data?.overview_response || null;
            serverData.cookies = p.cookies || {};
            saveConfig();
            saveAppData();
            saveCookies();
            setStatus('✅ Configuration and cookies imported');
            return true;
        } catch (e) {
            setStatus(`❌ Import error: ${e.message}`, true);
            return false;
        }
    }

    function downloadConfig() {
        try {
            const exportData = {
                config,
                app_data: {
                    application_payload: serverData.application_payload,
                    personal_payload: serverData.personal_payload,
                    overview_response: serverData.overview_response
                },
                cookies: serverData.cookies,
                export_date: new Date().toISOString(),
                version: '14.2'
            };
            const jsonString = JSON.stringify(exportData, null, 2);
            const blob = new Blob([jsonString], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ivac-config-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            setStatus('✅ Configuration downloaded as JSON file');
        } catch (e) {
            setStatus(`❌ Error downloading config: ${e.message}`, true);
        }
    }

    function uploadConfig(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = function(e) {
                try {
                    const content = e.target.result;
                    const importedData = JSON.parse(content);
                    if (!importedData.config) {
                        throw new Error('Invalid configuration file: missing config data');
                    }
                    config = {
                        ...config,
                        ...importedData.config
                    };
                    serverData.appointment_date = config.appiDate || "";
                    serverData.application_payload = importedData.app_data?.application_payload || null;
                    serverData.personal_payload = importedData.app_data?.personal_payload || null;
                    serverData.overview_response = importedData.app_data?.overview_response || null;
                    serverData.cookies = importedData.cookies || {};
                    saveConfig();
                    saveAppData();
                    saveCookies();
                    setStatus('✅ Configuration uploaded and applied successfully');
                    resolve(true);
                } catch (e) {
                    setStatus(`❌ Error parsing uploaded file: ${e.message}`, true);
                    reject(e);
                }
            };
            reader.onerror = function() {
                const error = new Error('Failed to read file');
                setStatus(`❌ Upload error: ${error.message}`, true);
                reject(error);
            };
            reader.readAsText(file);
        });
    }

    function logout() {
        try {
            localStorage.removeItem('token');
            localStorage.removeItem('access_token');
            localStorage.removeItem('lastAccessToken');
            sessionStorage.removeItem('token');
            sessionStorage.removeItem('access_token');
            localStorage.removeItem('ivac_app_data');
            localStorage.removeItem('ivac_cookies');
            serverData.access_token = null;
            serverData.application_payload = null;
            serverData.personal_payload = null;
            serverData.overview_response = null;
            serverData.cookies = {};
            document.getElementById('token-status').textContent = 'Not Set';
            setStatus('✅ Logged out');
        } catch (e) {
            setStatus(`❌ Error during logout: ${e.message}`, true);
        }
    }

    async function solveTurnstileCaptcha(a = 'login') {
        const s = SITE_KEYS[a];
        if (!s) {
            throw new Error(`No sitekey for ${a}`);
        }
        setCapSolverStatus('Creating task...');
        const t = {
            clientKey: CAPTCHA_API_KEY,
            task: {
                type: "AntiTurnstileTask",
                websiteURL: "https://payment.ivacbd.com",
                websiteKey: s,
                userAgent: navigator.userAgent
            }
        };
        const cr = await fetch(CAPSOLVER_API_URL, {
            method: "POST",
            body: JSON.stringify(t)
        });
        const td = await cr.json();
        if (td.errorId !== 0) {
            throw new Error(td.errorDescription || 'CapSolver error');
        }
        const ti = td.taskId;
        setCapSolverStatus(`Solving (ID: ${ti.substr(0,8)}...`);
        let tok,
            att = 0;
        while (att++ < 30 && !tok) {
            await new Promise(r => setTimeout(r, 1000));
            const rd = await fetch(CAPSOLVER_GET_TASK_URL, {
                method: "POST",
                body: JSON.stringify({
                    clientKey: CAPTCHA_API_KEY,
                    taskId: ti
                })
            }).then(r => r.json());
            if (rd.status === "ready") {
                tok = rd.solution.token;
                break;
            } else if (rd.errorId !== 0) {
                throw new Error(rd.errorDescription || 'CapSolver error');
            }
        }
        if (!tok) {
            throw new Error("Solving timed out");
        }
        setCapSolverStatus('✅ Solved');
        return tok;
    }

    // Payload Functions
    function getApplicationPayload(c) {
        return {
            highcom: config.highcom,
            webfile_id: config.webid,
            webfile_id_repeat: config.webid_repeat || config.webid,
            ivac_id: config.ivac_id,
            visa_type: config.visa_type,
            family_count: config.family.length.toString(),
            visit_purpose: config.visit_purpose,
            asweoi_erilfs: config.visit_purpose,
            y6e7uk_token_t6d8n3: c
        };
    }

    function getPersonalInfoPayload() {
        const p = {
            full_name: config.fullname,
            email_name: config.emailname,
            phone: config.mobileNumber,
            webfile_id: config.webid,
            webfile_id_repeat: config.webid_repeat || config.webid,
            family: {}
        };
        config.family.forEach((m, i) => {
            p.family[i + 1] = {
                webfile_no: m.webfile_no,
                name: m.name,
                again_webfile_no: m.again_webfile_no || m.webfile_no
            };
        });
        return p;
    }

    // ==================== UI COMPONENTS ====================
    function addRow(...c) {
        const r = el('div', 'ivac-row');
        c.forEach(c => r.appendChild(c));
        return r;
    }

    function addSection(parent) {
        const s = el('div', 'ivac-section');
        parent.appendChild(s);
        return s;
    }

    // Create Tab Structure
    function createTabs() {
        const tabsContainer = el('div', 'tabs-container');

        // Tab buttons - Only 3 tabs now
        const tabButtons = el('div', 'tab-buttons');

        const dataSubmitTabBtn = el('button', 'tab-btn active');
        dataSubmitTabBtn.setAttribute('data-tab', 'data-submit');
        dataSubmitTabBtn.innerHTML = '📝 Data Submit';

        const paymentTabBtn = el('button', 'tab-btn');
        paymentTabBtn.setAttribute('data-tab', 'payment');
        paymentTabBtn.innerHTML = '💳 Payment';

        const configTabBtn = el('button', 'tab-btn');
        configTabBtn.setAttribute('data-tab', 'configuration');
        configTabBtn.innerHTML = '⚙️ Configuration';

        tabButtons.appendChild(dataSubmitTabBtn);
        tabButtons.appendChild(paymentTabBtn);
        tabButtons.appendChild(configTabBtn);

        tabsContainer.appendChild(tabButtons);

        // Tab contents - Only 3 tabs now
        const tabContents = el('div', 'tab-contents');

        // Data Submit Tab
        const dataSubmitTab = el('div', 'tab-content');
        dataSubmitTab.id = 'data-submit-tab';
        dataSubmitTab.style.display = 'block';

        // Payment Tab
        const paymentTab = el('div', 'tab-content');
        paymentTab.id = 'payment-tab';
        paymentTab.style.display = 'none';

        // Configuration Tab
        const configTab = el('div', 'tab-content');
        configTab.id = 'configuration-tab';
        configTab.style.display = 'none';

        tabContents.appendChild(dataSubmitTab);
        tabContents.appendChild(paymentTab);
        tabContents.appendChild(configTab);

        tabsContainer.appendChild(tabContents);

        // Add event listeners for tab switching
        tabButtons.addEventListener('click', (e) => {
            if (e.target.classList.contains('tab-btn')) {
                const tabName = e.target.getAttribute('data-tab');
                switchTab(tabName);
            }
        });

        return { tabsContainer, dataSubmitTab, paymentTab, configTab };
    }

    // Enhanced Configuration Popup with Rate Limit Display
    function createConfigPopup() {
        const missions = [
            {value: "1", name: "DHAKA"},
            {value: "2", name: "CHITTAGONG"},
            {value: "3", name: "RAJSHAHI"},
            {value: "4", name: "SYLHET"},
            {value: "5", name: "KHULNA"}
        ];

        const ivacCenters = [
            {value: "17", name: "IVAC, DHAKA JFP"},
            {value: "2", name: "IVAC, RAJSHAHI"},
            {value: "3", name: "IVAC, KHULNA"},
            {value: "4", name: "IVAC, SYLHET"},
            {value: "5", name: "IVAC, CHITTAGONG"}
        ];

        const visaTypes = [
            {value: "13", name: "MEDICAL/ATTENDANT VISA"},
            {value: "1", name: "BUSINESS VISA"},
            {value: "6", name: "ENTRY VISA"},
            {value: "19", name: "DOUBLE ENTRY VISA"},
            {value: "2", name: "STUDENT VISA"},
            {value: "3", name: "TOURIST VISA"}
        ];

        const timeSlots = [
            "09:00 - 09:59", "10:00 - 10:59", "11:00 - 11:59",
            "12:00 - 12:59", "14:00 - 14:59", "15:00 - 15:59"
        ];

        const popup = el('div', 'config-popup');
        popup.style.display = 'none';
        popup.innerHTML = `
            <div class="ivac-header">
                <div class="ivac-title">⚙️ Advanced Configuration</div>
                <div class="ivac-close-btn" id="config-close-btn">×</div>
            </div>

            <!-- Rate Limit Display -->
            <div id="rate-limit-display" class="rate-limit-display" style="display: none;"></div>

            <div class="ivac-section">
                <div class="section-title">📋 Basic Information</div>
                <label>Appointment Date:</label>
                <input id="config-appiDate" class="ivac-input" type="date" value="${config.appiDate||''}">

                <label>High Commission:</label>
                <select id="config-highcom" class="ivac-select">
                    <option value="">Select Mission</option>
                    ${missions.map(o => `<option value="${o.value}" ${o.value===config.highcom?'selected':''}>${o.name}</option>`).join('')}
                </select>

                <label>IVAC Center:</label>
                <select id="config-ivac_id" class="ivac-select">
                    <option value="">Select IVAC Center</option>
                    ${ivacCenters.map(o => `<option value="${o.value}" ${o.value===config.ivac_id?'selected':''}>${o.name}</option>`).join('')}
                </select>

                <label>Visa Type:</label>
                <select id="config-visa_type" class="ivac-select">
                    <option value="">Select Visa Type</option>
                    ${visaTypes.map(o => `<option value="${o.value}" ${o.value===config.visa_type?'selected':''}>${o.name}</option>`).join('')}
                </select>

                <label>Visit Purpose:</label>
                <textarea id="config-visit_purpose" class="ivac-input" placeholder="Purpose of visit" style="height: 60px; resize: vertical;">${config.visit_purpose||''}</textarea>
            </div>

            <div class="ivac-section">
                <div class="section-title">👤 Personal Details</div>
                <label>Mobile Number:</label>
                <input id="config-mobileNumber" class="ivac-input" type="tel" value="${config.mobileNumber||''}" placeholder="01XXXXXXXXX">

                <label>Password:</label>
                <input id="config-password" class="ivac-input" type="password" value="${config.password||''}">

                <label>Email Address:</label>
                <input id="config-emailname" class="ivac-input" type="email" value="${config.emailname||''}">

                <label>Full Name:</label>
                <input id="config-fullname" class="ivac-input" value="${config.fullname||''}" placeholder="As per passport">

                <label>Webfile ID:</label>
                <input id="config-webid" class="ivac-input" value="${config.webid||''}">

                <label>Confirm Webfile ID:</label>
                <input id="config-webid_repeat" class="ivac-input" value="${config.webid_repeat||''}">
            </div>

            <div class="ivac-section">
                <div class="section-title">👨‍👩‍👧‍👦 Family Members (4 Members)</div>
                <label>Number of Family Members:</label>
                <select id="config-family-count" class="ivac-select">
                    ${Array.from({length: 11}, (_, i) =>
                                 `<option value="${i}" ${i.toString()===config.familyCount?'selected':''}>${i} Member${i !== 1 ? 's' : ''}</option>`
                                ).join('')}
                </select>

                <div class="family-format-info">
                    <strong>Format:</strong> Name (as per passport), Webfile Number (e.g., BGDDV860D325)
                </div>

                <div id="family-members" class="family-members-container"></div>
            </div>

            <div class="ivac-section">
                <div class="section-title">⏰ Slot Preferences</div>
                <label>Preferred Time Slot:</label>
                <select id="config-default-time" class="ivac-select">
                    <option value="">Select Default Time</option>
                    ${timeSlots.map(time =>
                                    `<option value="${time}" ${time===config.defaultTime?'selected':''}>${time}</option>`
                                   ).join('')}
                </select>

                <div class="setting-row">
                    <input type="checkbox" id="config-auto-select" ${config.autoSelectFirstAvailable ? 'checked' : ''}>
                    <label for="config-auto-select" class="setting-label">Auto-select first available slot</label>
                </div>
            </div>

            <div class="ivac-section">
                <div class="section-title">💾 Data Management</div>
                <div class="setting-row">
                    <input type="checkbox" id="config-remember-me" ${config.rememberMe ? 'checked' : ''}>
                    <label for="config-remember-me" class="setting-label">Remember Me</label>
                </div>
                <div id="config-remember-status" class="remember-status ${config.rememberMe ? 'active' : 'inactive'}">
                    ${config.rememberMe ? '✅ Remembering your data' : 'Remember Me is off'}
                </div>
                <button id="config-clear-remember" class="ivac-btn small red" style="${config.rememberMe ? 'display: block;' : 'display: none;'}">🗑️ Clear Remembered Data</button>
            </div>

            <div class="ivac-section">
                <div class="action-buttons">
                    <button id="save-config-btn" class="ivac-btn success">💾 Save Configuration</button>
                    <div class="button-row">
                        <button id="export-config-btn" class="ivac-btn primary">📤 Export Text</button>
                        <button id="import-config-btn" class="ivac-btn primary">📥 Import Text</button>
                    </div>
                    <div class="button-row">
                        <button id="download-config-btn" class="ivac-btn secondary">📥 Download JSON</button>
                        <button id="upload-config-btn" class="ivac-btn secondary">📤 Upload JSON</button>
                    </div>
                    <button id="refresh-config-btn" class="ivac-btn warning">🔄 Refresh from Storage</button>
                </div>
            </div>
        `;

        document.body.appendChild(popup);

        // Initialize family members
        renderFamilyMembers();

        // Event Listeners with status updates
        popup.querySelector('#config-family-count').addEventListener('change', (e) => {
            config.familyCount = e.target.value;
            updateFamilyMembers();
            setStatus(`✅ Family count updated to ${e.target.value} members`);
        });

        popup.querySelector('#config-default-time').addEventListener('change', (e) => {
            config.defaultTime = e.target.value;
            saveConfig();
            setStatus(`✅ Default time slot set to ${e.target.value}`);
        });

        popup.querySelector('#config-auto-select').addEventListener('change', (e) => {
            config.autoSelectFirstAvailable = e.target.checked;
            saveConfig();
            setStatus(`✅ Auto-select first available slot: ${e.target.checked ? 'ENABLED' : 'DISABLED'}`);
        });

        popup.querySelector('#config-remember-me').addEventListener('change', (e) => {
            toggleRememberMe(e.target.checked);
            setStatus(`✅ Remember Me: ${e.target.checked ? 'ENABLED' : 'DISABLED'}`);
        });

        popup.querySelector('#config-clear-remember').addEventListener('click', () => {
            if (confirm('Are you sure you want to clear all remembered data?')) {
                clearRememberMeData();
                updateRememberMeUI();
                setStatus('✅ All remembered data cleared');
            }
        });

        popup.querySelector('#save-config-btn').onclick = () => {
            config.appiDate = popup.querySelector('#config-appiDate').value.trim();
            config.highcom = popup.querySelector('#config-highcom').value;
            config.ivac_id = popup.querySelector('#config-ivac_id').value;
            config.visa_type = popup.querySelector('#config-visa_type').value;
            config.visit_purpose = popup.querySelector('#config-visit_purpose').value.trim();
            config.mobileNumber = popup.querySelector('#config-mobileNumber').value.trim();
            config.password = popup.querySelector('#config-password').value.trim();
            config.emailname = popup.querySelector('#config-emailname').value.trim();
            config.fullname = popup.querySelector('#config-fullname').value.trim();
            config.webid = popup.querySelector('#config-webid').value.trim();
            config.webid_repeat = popup.querySelector('#config-webid_repeat').value.trim();

            // Save family member data
            const familyInputs = popup.querySelectorAll('.family-member');
            config.family = Array.from(familyInputs).map(memberDiv => ({
                name: memberDiv.querySelector('.family-name').value.trim(),
                webfile_no: memberDiv.querySelector('.family-webfile').value.trim(),
                again_webfile_no: memberDiv.querySelector('.family-webfile-repeat').value.trim()
            }));

            serverData.appointment_date = config.appiDate;
            saveConfig();
            popup.style.display = 'none';
            setStatus('✅ Configuration saved successfully');
        };

        popup.querySelector('#export-config-btn').onclick = () => {
            exportConfig();
            setStatus('📤 Exporting configuration to text...');
        };

        popup.querySelector('#import-config-btn').onclick = () => {
            importPopup.querySelector('#import-json').value = '';
            importPopup.style.display = 'block';
            setStatus('📥 Ready to import configuration from text');
        };

        popup.querySelector('#download-config-btn').onclick = () => {
            downloadConfig();
            setStatus('💾 Downloading configuration as JSON file...');
        };

        popup.querySelector('#upload-config-btn').onclick = () => {
            uploadPopup.style.display = 'block';
            setStatus('📁 Ready to upload configuration JSON file');
        };

        popup.querySelector('#refresh-config-btn').onclick = () => {
            updateConfigFromStorage();
            popup.querySelector('#config-appiDate').value = config.appiDate || '';
            popup.querySelector('#config-highcom').value = config.highcom || '';
            popup.querySelector('#config-ivac_id').value = config.ivac_id || '';
            popup.querySelector('#config-visa_type').value = config.visa_type || '';
            popup.querySelector('#config-visit_purpose').value = config.visit_purpose || '';
            popup.querySelector('#config-mobileNumber').value = config.mobileNumber || '';
            popup.querySelector('#config-password').value = config.password || '';
            popup.querySelector('#config-emailname').value = config.emailname || '';
            popup.querySelector('#config-fullname').value = config.fullname || '';
            popup.querySelector('#config-webid').value = config.webid || '';
            popup.querySelector('#config-webid_repeat').value = config.webid_repeat || '';
            renderFamilyMembers();
            setStatus('🔄 Configuration refreshed from storage');
        };

        popup.querySelector('#config-close-btn').onclick = () => {
            popup.style.display = 'none';
            setStatus('⚙️ Configuration panel closed');
        };

        // Create upload popup
        uploadPopup = el('div', 'upload-popup');
        uploadPopup.style.display = 'none';
        uploadPopup.innerHTML = `
            <div class="ivac-header">
                <div class="ivac-title">Upload Configuration</div>
                <div class="ivac-close-btn" id="upload-close-btn">×</div>
            </div>
            <div class="ivac-section">
                <label>Select JSON Configuration File:</label>
                <input type="file" id="config-file-input" accept=".json" class="ivac-input">
                <div class="ivac-row">
                    <button id="upload-save-btn" class="ivac-btn success">📤 Upload</button>
                    <button id="upload-cancel-btn" class="ivac-btn danger">❌ Cancel</button>
                </div>
            </div>
        `;
        document.body.appendChild(uploadPopup);
        uploadPopup.querySelector('#upload-close-btn').onclick = () => {
            uploadPopup.style.display = 'none';
            setStatus('❌ Upload cancelled');
        };
        uploadPopup.querySelector('#upload-cancel-btn').onclick = () => {
            uploadPopup.style.display = 'none';
            setStatus('❌ Upload cancelled');
        };

        const fileInput = uploadPopup.querySelector('#config-file-input');
        uploadPopup.querySelector('#upload-save-btn').onclick = async () => {
            const file = fileInput.files[0];
            if (!file) {
                setStatus('❌ Please select a file first', true);
                return;
            }
            if (!file.name.endsWith('.json')) {
                setStatus('❌ Please select a JSON file', true);
                return;
            }
            try {
                setStatus('📤 Uploading configuration file...');
                await uploadConfig(file);
                uploadPopup.style.display = 'none';
                fileInput.value = '';
                popup.querySelector('#config-appiDate').value = config.appiDate || '';
                popup.querySelector('#config-highcom').value = config.highcom || '';
                popup.querySelector('#config-ivac_id').value = config.ivac_id || '';
                popup.querySelector('#config-visa_type').value = config.visa_type || '';
                popup.querySelector('#config-visit_purpose').value = config.visit_purpose || '';
                popup.querySelector('#config-mobileNumber').value = config.mobileNumber || '';
                popup.querySelector('#config-password').value = config.password || '';
                popup.querySelector('#config-emailname').value = config.emailname || '';
                popup.querySelector('#config-fullname').value = config.fullname || '';
                popup.querySelector('#config-webid').value = config.webid || '';
                popup.querySelector('#config-webid_repeat').value = config.webid_repeat || '';
                renderFamilyMembers();
                setStatus('✅ Configuration uploaded and applied successfully');
            } catch (e) {
                // Error handled in uploadConfig
            }
        };

        importPopup = el('div', 'import-popup');
        importPopup.style.display = 'none';
        importPopup.innerHTML = `<div class="ivac-header"><div class="ivac-title">Import Configuration</div><div class="ivac-close-btn" id="import-close-btn">×</div></div><div class="ivac-section"><label>Paste Configuration JSON:</label><textarea id="import-json" class="ivac-input" style="height: 200px; resize: vertical;"></textarea><div class="ivac-row"><button id="import-save-btn" class="ivac-btn success">💾 Save</button><button id="import-cancel-btn" class="ivac-btn danger">❌ Cancel</button></div></div>`;
        document.body.appendChild(importPopup);
        importPopup.querySelector('#import-close-btn').onclick = () => {
            importPopup.style.display = 'none';
            setStatus('❌ Import cancelled');
        };
        importPopup.querySelector('#import-cancel-btn').onclick = () => {
            importPopup.style.display = 'none';
            setStatus('❌ Import cancelled');
        };
        importPopup.querySelector('#import-save-btn').onclick = () => {
            const c = importPopup.querySelector('#import-json').value;
            if (c) {
                setStatus('📥 Importing configuration from text...');
                if (importConfig(c)) {
                    renderFamilyMembers();
                    popup.querySelector('#config-appiDate').value = config.appiDate || '';
                    popup.querySelector('#config-highcom').value = config.highcom || '';
                    popup.querySelector('#config-ivac_id').value = config.ivac_id || '';
                    popup.querySelector('#config-visa_type').value = config.visa_type || '';
                    popup.querySelector('#config-visit_purpose').value = config.visit_purpose || '';
                    popup.querySelector('#config-mobileNumber').value = config.mobileNumber || '';
                    popup.querySelector('#config-password').value = config.password || '';
                    popup.querySelector('#config-emailname').value = config.emailname || '';
                    popup.querySelector('#config-fullname').value = config.fullname || '';
                    popup.querySelector('#config-webid').value = config.webid || '';
                    popup.querySelector('#config-webid_repeat').value = config.webid_repeat || '';
                    importPopup.style.display = 'none';
                    setStatus('✅ Configuration imported successfully');
                }
            } else {
                setStatus('❌ Please paste configuration JSON first', true);
            }
        };

        exportPopup = el('div', 'export-popup');
        exportPopup.style.display = 'none';
        exportPopup.innerHTML = `<div class="ivac-header"><div class="ivac-title">Exported Configuration</div><div class="ivac-close-btn" id="export-close-btn">×</div></div><div class="ivac-section"><label>Exported JSON:</label><textarea id="export-json" class="ivac-input" style="height: 200px; resize: vertical;" readonly></textarea><div class="ivac-row"><button id="export-copy-btn" class="ivac-btn primary">📋 Copy</button><button id="export-close-btn2" class="ivac-btn danger">❌ Close</button></div></div>`;
        document.body.appendChild(exportPopup);
        exportPopup.querySelector('#export-close-btn').onclick = () => {
            exportPopup.style.display = 'none';
            setStatus('📤 Export view closed');
        };
        exportPopup.querySelector('#export-close-btn2').onclick = () => {
            exportPopup.style.display = 'none';
            setStatus('📤 Export view closed');
        };
        exportPopup.querySelector('#export-copy-btn').onclick = () => {
            const j = exportPopup.querySelector('#export-json').value;
            navigator.clipboard.writeText(j).then(() => {
                exportPopup.querySelector('#export-copy-btn').innerHTML = '✅ Copied!';
                setTimeout(() => exportPopup.querySelector('#export-copy-btn').innerHTML = '📋 Copy', 2000);
                setStatus('✅ Configuration copied to clipboard');
            }).catch(e => {
                setStatus(`❌ Error copying: ${e.message}`, true);
            });
        };

        makeDraggable(popup, popup.querySelector('.ivac-header'));
        makeDraggable(importPopup, importPopup.querySelector('.ivac-header'));
        makeDraggable(exportPopup, exportPopup.querySelector('.ivac-header'));
        makeDraggable(uploadPopup, uploadPopup.querySelector('.ivac-header'));
        return popup;
    }

    function updateConfigFromStorage() {
        loadConfig();
        loadAppData();
        loadRememberMeData();
    }

    // ==================== MAIN PANEL CREATION ====================
    const panel = el('div', 'ivac-panel');
    panel.id = 'ivac-panel';

    const header = el('div', 'ivac-header');
    header.innerHTML = '<div class="ivac-title">IVAC PAYMENT PANEL</div><div class="ivac-sub">Ultimate Panel v14.2</div>';
    const minimizeBtn = el('div', 'ivac-close-btn');
    minimizeBtn.innerHTML = '−';
    minimizeBtn.onclick = () => {
        panel.classList.toggle('minimized');
        minimizeBtn.innerHTML = panel.classList.contains('minimized') ? '+' : '−';
    };
    const closeBtn = el('div', 'ivac-close-btn');
    closeBtn.innerHTML = '×';
    closeBtn.onclick = () => confirm('Close panel?') && panel.remove();
    header.append(minimizeBtn, closeBtn);
    panel.appendChild(header);

    const stepIndicator = el('div', 'step-indicator');
    stepIndicator.id = 'step-indicator';
    stepIndicator.textContent = 'Data Submission';
    stepIndicator.style.background = 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)';
    panel.appendChild(stepIndicator);

    const statusBox = el('div', 'ivac-status');
    statusBox.id = 'ivac-status';
    statusBox.textContent = 'Ready - Enhanced API response handling active';
    panel.appendChild(statusBox);

    const capsolverStatus = el('div', 'capsolver-status');
    capsolverStatus.id = 'capsolver-status';
    capsolverStatus.textContent = 'CapSolver: Ready';
    panel.appendChild(capsolverStatus);

    const userInfoBox = el('div', 'user-info');
    userInfoBox.innerHTML = `<div class="token-indicator"></div><div class="user-info-text">Token: <span id="token-status">Not Set</span></div>`;
    panel.appendChild(userInfoBox);

    // Create tabs structure (only 3 tabs)
    const { tabsContainer, dataSubmitTab, paymentTab, configTab } = createTabs();
    panel.appendChild(tabsContainer);

    // Create UI Sections for each tab

    // Data Submit Tab Content
    const authSection = addSection(dataSubmitTab);
    const btnLogout = el('button', 'ivac-btn small danger');
    btnLogout.innerHTML = '🚪 Logout';
    btnLogout.onclick = () => {
        if (confirm('Logout?')) {
            logout();
            setStatus('✅ Logged out successfully');
        }
    };
    authSection.appendChild(addRow(btnLogout));

    // First row: Application
    const appSection = addSection(dataSubmitTab);
    const btnApp = el('button', 'ivac-btn success');
    btnApp.innerHTML = '📝 Application';
    appSection.appendChild(addRow(btnApp));

    // Second row: Personal and Overview
    const personalSection = addSection(dataSubmitTab);
    const btnPersonal = el('button', 'ivac-btn primary');
    btnPersonal.innerHTML = '👤 Personal';
    const btnOverview = el('button', 'ivac-btn secondary');
    btnOverview.innerHTML = '📊 Overview';
    personalSection.appendChild(addRow(btnPersonal, btnOverview));

    const cancelSection = addSection(dataSubmitTab);
    const btnCancelRequests = el('button', 'ivac-btn danger');
    btnCancelRequests.innerHTML = '❌ Cancel Requests';
    btnCancelRequests.onclick = () => {
        if (!activeRequests.size) {
            setStatus('No pending requests');
            return;
        }
        activeRequests.forEach(c => c.abort());
        activeRequests.clear();
        setStatus('✅ All pending requests cancelled');
    };
    cancelSection.appendChild(addRow(btnCancelRequests));

    // Payment Tab Content - ENHANCED WITH CAPTCHA IMAGE AND RELOAD BUTTON
    const paymentOtpSection = addSection(paymentTab);
    const btnSendOtp = el('button', 'ivac-btn success');
    btnSendOtp.innerHTML = '📤 Send OTP';
    const btnResendOtp = el('button', 'ivac-btn warning');
    btnResendOtp.innerHTML = '🔄 Resend';
    paymentOtpSection.appendChild(addRow(btnSendOtp, btnResendOtp));
    const payOtpInput = el('input', 'ivac-input');
    payOtpInput.id = 'pay-otp-input';
    payOtpInput.placeholder = 'Payment OTP (any format)';
    const btnVerifyOtp = el('button', 'ivac-btn small primary');
    btnVerifyOtp.innerHTML = '✅ Verify';
    paymentOtpSection.appendChild(addRow(payOtpInput, btnVerifyOtp));

    const appointmentSection = addSection(paymentTab);
    const appointmentInput = el('input', 'ivac-input');
    appointmentInput.id = 'appointment-input';
    appointmentInput.placeholder = 'YYYY-MM-DD';
    appointmentInput.type = 'date';
    appointmentInput.value = config.appiDate || '';
    const btnSlotLoad = el('button', 'ivac-btn success');
    btnSlotLoad.innerHTML = '⏰ Load Slots';
    appointmentSection.appendChild(addRow(appointmentInput, btnSlotLoad));

    // Enhanced Slot Selection with Dropdown
    const slotSelect = el('select', 'ivac-select');
    slotSelect.id = 'payment-slot-select';
    slotSelect.innerHTML = `
        <option value="09:00 - 09:59">09:00 - 09:59</option>
        <option value="10:00 - 10:59">10:00 - 10:59</option>
    `;

    const slotInfo = el('div', 'slot-info');
    slotInfo.id = 'slot-info';
    slotInfo.innerHTML = '<div class="slot-summary">Select a time slot</div>';

    slotSelect.onchange = () => {
        serverData.appointment_time_final = slotSelect.value;
        saveAppData();
        setStatus(`✅ Selected time slot: ${slotSelect.value}`);
    };

    appointmentSection.append(slotSelect, slotInfo);

    // ENHANCED CAPTCHA SECTION WITH RELOAD BUTTON
    const captchaSection = addSection(paymentTab);

    // First row: Generate and Reload buttons
    const btnGenerateCaptcha = el('button', 'ivac-btn primary');
    btnGenerateCaptcha.innerHTML = '🔄 Generate Captcha';
    const btnReloadCaptcha = el('button', 'ivac-btn warning');
    btnReloadCaptcha.innerHTML = '🔄 Reload Captcha';
    captchaSection.appendChild(addRow(btnGenerateCaptcha, btnReloadCaptcha));

    // Second row: Verify button
    const btnVerifyCaptcha = el('button', 'ivac-btn success');
    btnVerifyCaptcha.innerHTML = '✅ Verify Captcha';
    captchaSection.appendChild(addRow(btnVerifyCaptcha));

    // Create captcha image element FIRST (this is important)
    const captchaImage = el('img', 'captcha-image');
    captchaImage.id = 'payment-captcha-image';
    Object.assign(captchaImage.style, {
        display: 'none',
        maxWidth: '100%',
        height: 'auto',
        border: '2px solid #4facfe',
        borderRadius: '8px',
        margin: '10px 0px',
        background: 'white',
        padding: '10px'
    });
    captchaSection.appendChild(captchaImage);

    // Then captcha ID display
    const captchaIdDisplay = el('div', 'captcha-id-display');
    captchaIdDisplay.id = 'captcha-id-display';
    captchaIdDisplay.textContent = 'Captcha ID: Not generated';
    captchaIdDisplay.style.fontSize = '12px';
    captchaIdDisplay.style.color = '#fbbf24';
    captchaIdDisplay.style.margin = '5px 0';
    captchaIdDisplay.style.textAlign = 'center';
    captchaIdDisplay.style.display = 'none';
    captchaSection.appendChild(captchaIdDisplay);

    // Then input field
    const captchaInput = el('input', 'ivac-input');
    captchaInput.id = 'payment-captcha-input';
    captchaInput.placeholder = 'Enter captcha text';
    captchaSection.appendChild(captchaInput);

    // Then status
    const captchaStatus = el('div', 'captcha-status');
    captchaStatus.id = 'payment-captcha-status';
    captchaStatus.textContent = 'Captcha not generated';
    captchaStatus.style.fontSize = '12px';
    captchaStatus.style.textAlign = 'center';
    captchaStatus.style.margin = '5px 0';
    captchaSection.appendChild(captchaStatus);

    // Action Buttons Section
    const actionButtonsSection = addSection(paymentTab);

    // Create the three buttons in one row
    const btnInjectTime = el('button', 'ivac-btn primary');
    btnInjectTime.innerHTML = '⏰ Time';
    const btnPayNow = el('button', 'ivac-btn success');
    btnPayNow.id = 'btn-pay-now';
    btnPayNow.innerHTML = '💳 Pay Now';
    const btnCopyLink = el('button', 'ivac-btn danger');
    btnCopyLink.id = 'btn-copy-link';
    btnCopyLink.innerHTML = '📋 Copy';

    // Add all three buttons in one row
    actionButtonsSection.appendChild(addRow(btnInjectTime, btnPayNow, btnCopyLink));

    // Configuration Tab Content
    const configActionsSection = addSection(configTab);
    const btnConfig = el('button', 'ivac-btn primary');
    btnConfig.innerHTML = '⚙️ Files Configuration';
    const configPopup = createConfigPopup();
    btnConfig.onclick = () => {
        configPopup.style.display = 'block';
        setStatus('⚙️ Configuration panel opened');
    };

    const btnExport = el('button', 'ivac-btn secondary');
    btnExport.innerHTML = '📤 Export Config';
    btnExport.onclick = () => {
        exportConfig();
        setStatus('📤 Exporting configuration...');
    };

    const btnImport = el('button', 'ivac-btn secondary');
    btnImport.innerHTML = '📥 Import Config';
    btnImport.onclick = () => {
        importPopup.querySelector('#import-json').value = '';
        importPopup.style.display = 'block';
        setStatus('📥 Ready to import configuration');
    };

    const btnDownload = el('button', 'ivac-btn success');
    btnDownload.innerHTML = '💾 Download JSON';
    btnDownload.onclick = () => {
        downloadConfig();
        setStatus('💾 Downloading configuration...');
    };

    const btnUpload = el('button', 'ivac-btn warning');
    btnUpload.innerHTML = '📁 Upload JSON';
    btnUpload.onclick = () => {
        uploadPopup.style.display = 'block';
        setStatus('📁 Ready to upload configuration file');
    };

    configActionsSection.appendChild(addRow(btnConfig));
    configActionsSection.appendChild(addRow(btnExport, btnImport));
    configActionsSection.appendChild(addRow(btnDownload, btnUpload));

    const configInfoSection = addSection(configTab);
    configInfoSection.innerHTML = `
        <div class="config-summary">
            <div class="section-title">📊 Current Configuration</div>
            <div class="config-item"><strong>Highcom:</strong> <span id="config-highcom-display">${config.highcom || 'Not set'}</span></div>
            <div class="config-item"><strong>IVAC ID:</strong> <span id="config-ivacid-display">${config.ivac_id || 'Not set'}</span></div>
            <div class="config-item"><strong>Visa Type:</strong> <span id="config-visatype-display">${config.visa_type || 'Not set'}</span></div>
            <div class="config-item"><strong>Webfile ID:</strong> <span id="config-webid-display">${config.webid || 'Not set'}</span></div>
            <div class="config-item"><strong>Family Members:</strong> <span id="config-family-display">${config.familyCount || '0'}</span></div>
            <div class="remember-status ${config.rememberMe ? 'active' : 'inactive'}" style="margin-top: 10px;">
                Remember Me: <strong>${config.rememberMe ? '✅ ACTIVE' : '❌ INACTIVE'}</strong>
            </div>
        </div>
    `;

    // Assign button actions
    btnApp.onclick = btnAppAction;
    btnPersonal.onclick = btnPersonalAction;
    btnOverview.onclick = btnOverviewAction;
    btnSendOtp.onclick = () => sendOTP(false);
    btnResendOtp.onclick = () => sendOTP(true);
    btnVerifyOtp.onclick = btnVerifyOtpAction;
    btnSlotLoad.onclick = btnSlotLoadAction;
    btnInjectTime.onclick = injectTimeSlots;
    btnPayNow.onclick = btnPayNowAction;

    // Enhanced captcha button handlers
    btnGenerateCaptcha.onclick = async () => {
        console.log('[CAPTCHA] Generate button clicked');

        // Reset previous captcha
        resetCaptchaUI();

        // Small delay to ensure UI is reset
        await new Promise(resolve => setTimeout(resolve, 100));

        await generateCaptcha();
    };

    // NEW: Reload captcha button handler
    btnReloadCaptcha.onclick = async () => {
        console.log('[CAPTCHA] Reload button clicked');
        await reloadCaptcha();
    };

    btnVerifyCaptcha.onclick = verifyCaptcha;

    btnCopyLink.onclick = () => {
        if (!serverData.payment_link) {
            setStatus('❌ No payment link available', true);
            return;
        }
        navigator.clipboard.writeText(serverData.payment_link).then(() => {
            btnCopyLink.innerHTML = '✅ Copied!';
            setTimeout(() => btnCopyLink.innerHTML = '📋 COPY', 2000);
            setStatus('✅ Payment link copied to clipboard');
        }).catch(e => {
            setStatus(`❌ Error copying: ${e.message}`, true);
        });
    };

    // ==================== ENHANCED CSS STYLES ====================
    const style = document.createElement('style');
    style.innerHTML = `
        .ivac-panel, .config-popup, .import-popup, .export-popup, .upload-popup {
            position: fixed !important;
            top: 0;
            left: 0;
            width: 450px !important;
            max-width: 90vw !important;
            max-height: 85vh !important;
            overflow-y: auto !important;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%) !important;
            border: 1px solid rgba(255,255,255,0.15) !important;
            border-radius: 16px !important;
            color: #ffffff !important;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif !important;
            z-index: 10000000 !important;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3), 0 0 0 1px rgba(255,255,255,0.1) !important;
            backdrop-filter: blur(10px) !important;
            padding: 20px;
        }

        .ivac-panel.minimized {
            width: auto !important;
            height: 70px !important;
            overflow: hidden !important;
        }

        /* Rate Limit Display */
        .rate-limit-display {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%) !important;
            color: white !important;
            padding: 10px !important;
            border-radius: 8px !important;
            text-align: center !important;
            font-weight: 600 !important;
            margin-bottom: 15px !important;
            animation: pulse 2s infinite !important;
        }

        .ivac-header {
            display: flex !important;
            align-items: center !important;
            justify-content: space-between !important;
            margin-bottom: 12px !important;
            padding-bottom: 12px !important;
            border-bottom: 1px solid rgba(255,255,255,0.2) !important;
            cursor: move !important;
            user-select: none !important;
        }

        .ivac-title {
            font-weight: 700 !important;
            font-size: 18px !important;
            background: linear-gradient(135deg, #fff 0%, #a8edea 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .ivac-sub {
            font-size: 12px !important;
            opacity: 0.8 !important;
            color: #a8edea !important;
        }

        /* Modern Button Styles */
        .ivac-btn {
            flex: 1 !important;
            padding: 12px 16px !important;
            border-radius: 12px !important;
            border: none !important;
            color: #ffffff !important;
            font-size: 13px !important;
            font-weight: 600 !important;
            cursor: pointer !important;
            transition: all 0.3s ease !important;
            position: relative !important;
            overflow: hidden !important;
        }

        .ivac-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }

        .ivac-btn:hover::before {
            left: 100%;
        }

        .ivac-btn:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 8px 20px rgba(0,0,0,0.3) !important;
        }

        .ivac-btn:active {
            transform: translateY(0) !important;
        }

        .ivac-btn.success {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%) !important;
            color: #1a3c2e !important;
        }

        .ivac-btn.primary {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%) !important;
        }

        .ivac-btn.secondary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        }

        .ivac-btn.warning {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%) !important;
        }

        .ivac-btn.danger {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%) !important;
        }

        .ivac-btn.small {
            font-size: 12px !important;
        }

        /* Section Styles */
        .ivac-section {
            background: rgba(255,255,255,0.08) !important;
            border-radius: 12px !important;
            padding: 16px !important;
            margin-bottom: 12px !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
            backdrop-filter: blur(10px) !important;
            max-width: 100% !important;
            color: #a8edea !important;
        }

        .section-title {
            font-size: 14px !important;
            font-weight: 600 !important;
            margin-bottom: 12px !important;
            color: #a8edea !important;
            display: flex !important;
            align-items: center !important;
            gap: 8px !important;
        }

        .ivac-row {
            display: flex !important;
            gap: 10px !important;
            margin-bottom: 10px !important;
            align-items: center !important;

        }

        /* Input Styles */
        .ivac-input, .ivac-select {
            width: 50% !important;
            padding: 12px 16px !important;
            border-radius: 10px !important;
            border: 1px solid rgba(255,255,255,0.2) !important;
            background: rgba(0,0,0,0.3) !important;
            color: #ffffff !important;
            font-size: 14px !important;
            transition: all 0.3s ease !important;
        }

        .import-popup .ivac-input {
            width: 100% !important;
        }

       .export-popup .ivac-input {
            width: 100% !important;
       }

        .ivac-input:focus, .ivac-select:focus {
            outline: none !important;
            border-color: #4facfe !important;
            box-shadow: 0 0 0 2px rgba(79, 172, 254, 0.2) !important;
        }

        /* Family Member Styles */
        .family-members-container {
            margin-top: 12px !important;
        }

        .family-member {
            background: rgba(0,0,0,0.2) !important;
            border-radius: 10px !important;
            padding: 12px !important;
            margin-bottom: 10px !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
        }

        .family-member-header {
            display: flex !important;
            justify-content: space-between !important;
            align-items: center !important;
            margin-bottom: 10px !important;
        }

        .family-member-title {
            font-size: 13px !important;
            font-weight: 600 !important;
            color: #4facfe !important;
        }

        .family-format-info {
            font-size: 12px !important;
            color: #a8edea !important;
            margin-bottom: 10px !important;
            padding: 8px !important;
            background: rgba(0,0,0,0.2) !important;
            border-radius: 6px !important;
        }

        /* Slot Info Styles */
        .slot-info {
            margin-top: 10px !important;
            padding: 12px !important;
            border-radius: 10px !important;
            font-size: 13px !important;
        }

        .slot-info.available {
            background: rgba(67, 233, 123, 0.15) !important;
            border: 1px solid rgba(67, 233, 123, 0.3) !important;
        }

        .slot-info.unavailable {
            background: rgba(255, 107, 107, 0.15) !important;
            border: 1px solid rgba(255, 107, 107, 0.3) !important;
        }

        .slot-summary {
            display: flex !important;
            justify-content: space-between !important;
            align-items: center !important;
            margin-bottom: 8px !important;
        }

        .auto-select-badge {
            background: rgba(67, 233, 123, 0.3) !important;
            color: #43e97b !important;
            padding: 4px 8px !important;
            border-radius: 12px !important;
            font-size: 10px !important;
            font-weight: 600 !important;
        }

        /* Tab Styles */
        .tabs-container {
            width: 100% !important;
        }

        .tab-buttons {
            display: flex !important;
            background: rgba(0,0,0,0.3) !important;
            border-radius: 12px !important;
            margin-bottom: 16px !important;
            overflow: hidden !important;
            padding: 4px !important;
        }

        .tab-btn {
            flex: 1 !important;
            padding: 10px 8px !important;
            background: transparent !important;
            border: none !important;
            color: rgba(255,255,255,0.7) !important;
            font-size: 11px !important;
            cursor: pointer !important;
            transition: all 0.3s ease !important;
            border-radius: 8px !important;
        }

        .tab-btn:hover {
            background: rgba(255,255,255,0.1) !important;
            color: #fff !important;
        }

        .tab-btn.active {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%) !important;
            color: #fff !important;
            box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3) !important;
        }

        /* Status Indicators */
        .step-indicator {
            font-size: 12px !important;
            padding: 8px 12px !important;
            border-radius: 20px !important;
            color: white !important;
            font-weight: bold !important;
            text-align: center !important;
            margin: 8px 0 !important;
            font-family: monospace !important;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2) !important;
        }

        .ivac-status {
            font-size: 12px !important;
            padding: 12px !important;
            border-radius: 10px !important;
            background: rgba(0,0,0,0.35) !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
            text-align: center !important;
            margin: 8px 0 !important;
            color: #fff;
        }

        .capsolver-status {
            font-size: 11px !important;
            color: #fbbf24 !important;
            margin-top: 3px !important;
            text-align: center !important;
        }

        .user-info {
            display: flex !important;
            align-items: center !important;
            gap: 8px !important;
            padding: 8px !important;
            background: rgba(34,211,208,0.1) !important;
            border-radius: 8px !important;
            margin: 8px 0 !important;
        }

        .user-info-text {
            font-size: 12px !important;
            color: #34d3d0 !important;
        }

        .token-indicator {
            width: 8px !important;
            height: 8px !important;
            border-radius: 50% !important;
            background: #10b981 !important;
            animation: pulse 2s infinite !important;
        }

        /* CAPTCHA IMAGE STYLES - FIXED */
        .captcha-image {
            display: none;
            max-width: 100%;
            height: auto;
            border: 2px solid #4facfe;
            border-radius: 8px;
            margin: 10px 0px;
            background: white;
            padding: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }

        .captcha-image[src]:not([src=""]) {
            display: block !important;
        }

        .captcha-id-display {
            font-size: 12px;
            color: #fbbf24;
            margin: 5px 0;
            text-align: center;
            font-family: monospace;
            background: rgba(251, 191, 36, 0.1);
            padding: 4px 8px;
            border-radius: 4px;
            border: 1px solid rgba(251, 191, 36, 0.2);
            display: none;
        }

        #payment-captcha-input {
            margin-top: 10px;
        }

        /* Remember Me Styles */
        .remember-status {
            font-size: 12px !important;
            padding: 10px !important;
            border-radius: 8px !important;
            text-align: center !important;
            margin: 8px 0 !important;
            font-weight: 600 !important;
        }

        .remember-status.active {
            background: rgba(67, 233, 123, 0.2) !important;
            color: #43e97b !important;
            border: 1px solid rgba(67, 233, 123, 0.3) !important;
        }

        .remember-status.inactive {
            background: rgba(255,255,255,0.1) !important;
            color: rgba(255,255,255,0.7) !important;
            border: 1px solid rgba(255,255,255,0.2) !important;
        }

        .remember-me-row {
            display: flex !important;
            align-items: center !important;
            gap: 10px !important;
            margin-bottom: 10px !important;
        }

        .remember-me-label {
            font-size: 14px !important;
            color: #ffffff !important;
            cursor: pointer !important;
            font-weight: 600 !important;
        }

        .remember-checkbox {
            width: 16px !important;
            height: 16px !important;
            cursor: pointer !important;
        }

        .setting-row {
            display: flex !important;
            align-items: center !important;
            gap: 10px !important;
            margin-bottom: 10px !important;
        }

        .setting-label {
            font-size: 14px !important;
            color: #ffffff !important;
            cursor: pointer !important;
        }

        /* Action Buttons Container */
        .action-buttons {
            display: flex !important;
            flex-direction: column !important;
            gap: 10px !important;
        }

        .button-row {
            display: flex !important;
            gap: 10px !important;
        }

        /* Config Summary */
        .config-summary {
            font-size: 13px !important;
        }

        .config-item {
            display: flex !important;
            justify-content: space-between !important;
            margin-bottom: 8px !important;
            padding: 6px 0 !important;
            border-bottom: 1px solid rgba(255,255,255,0.1) !important;
        }

        .config-popup .ivac-select {
           width: 100% !important;
        }

      .config-popup .ivac-input {
          width: 92% !important;
        }

        /* Close Button */
        .ivac-close-btn {
            width: 24px !important;
            height: 24px !important;
            border-radius: 8px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            cursor: pointer !important;
            font-size: 16px !important;
            background: rgba(255,255,255,0.1) !important;
            border: 1px solid rgba(255,255,255,0.2) !important;
            transition: all 0.3s ease !important;
        }

        .ivac-close-btn:hover {
            background: rgba(255,255,255,0.2) !important;
            transform: scale(1.1) !important;
        }

        /* Responsive Design */
        @media (max-width: 600px) {
            .ivac-panel, .config-popup, .import-popup, .export-popup, .upload-popup {
                width: 95vw !important;
                font-size: 14px !important;
                left: 2.5vw !important;
            }

            .ivac-btn {
                font-size: 13px !important;
                padding: 10px 12px !important;
            }

            .tab-btn {
                font-size: 10px !important;
                padding: 8px 4px !important;
            }
        }

        /* Animation Keyframes */
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }

        .ivac-panel {
            animation: slideIn 0.5s ease-out !important;
        }
    `;
    document.head.appendChild(style);

    // IMPROVED DRAG FUNCTIONALITY
    function makeDraggable(element, handle) {
        let isDragging = false;
        let currentX;
        let currentY;
        let initialX;
        let initialY;
        let xOffset = 0;
        let yOffset = 0;

        // Load saved position
        const savedPosition = localStorage.getItem('ivac-panel-pos');
        if (savedPosition) {
            try {
                const pos = JSON.parse(savedPosition);
                element.style.left = pos.left + 'px';
                element.style.top = pos.top + 'px';
                xOffset = pos.left;
                yOffset = pos.top;
            } catch (e) {
                console.warn('Failed to load saved position:', e);
            }
        }

        handle.addEventListener('mousedown', dragStart);
        handle.addEventListener('touchstart', dragStart, { passive: true });

        function dragStart(e) {
            if (e.type === 'touchstart') {
                initialX = e.touches[0].clientX - xOffset;
                initialY = e.touches[0].clientY - yOffset;
            } else {
                initialX = e.clientX - xOffset;
                initialY = e.clientY - yOffset;
            }

            if (e.target === handle || handle.contains(e.target)) {
                isDragging = true;
                document.addEventListener('mousemove', drag);
                document.addEventListener('touchmove', drag, { passive: false });
                document.addEventListener('mouseup', dragEnd);
                document.addEventListener('touchend', dragEnd);

                element.style.cursor = 'grabbing';
                element.style.userSelect = 'none';
            }
        }

        function drag(e) {
            if (!isDragging) return;

            e.preventDefault();

            if (e.type === 'touchmove') {
                currentX = e.touches[0].clientX - initialX;
                currentY = e.touches[0].clientY - initialY;
            } else {
                currentX = e.clientX - initialX;
                currentY = e.clientY - initialY;
            }

            xOffset = currentX;
            yOffset = currentY;

            setTranslate(currentX, currentY, element);
        }

        function dragEnd() {
            isDragging = false;
            document.removeEventListener('mousemove', drag);
            document.removeEventListener('touchmove', drag);
            document.removeEventListener('mouseup', dragEnd);
            document.removeEventListener('touchend', dragEnd);

            element.style.cursor = 'grab';
            element.style.userSelect = 'auto';

            // Save position
            localStorage.setItem('ivac-panel-pos', JSON.stringify({
                left: xOffset,
                top: yOffset
            }));
        }

        function setTranslate(xPos, yPos, el) {
            // Boundary checking
            const maxX = window.innerWidth - el.offsetWidth;
            const maxY = window.innerHeight - el.offsetHeight;

            xPos = Math.max(0, Math.min(xPos, maxX));
            yPos = Math.max(0, Math.min(yPos, maxY));

            el.style.left = xPos + 'px';
            el.style.top = yPos + 'px';
        }
    }

    // Session Monitor
    function setupSessionMonitor() {
        setInterval(() => {
            if (serverData.session_data.is_logged_in) {
                updateSessionActivity();
            }
        }, 60000); // Update every minute
    }

    // Panel State Management
    function updatePanelLoginState(isLoggedIn) {
        serverData.session_data.is_logged_in = isLoggedIn;
        if (isLoggedIn) {
            setStatus('✅ Session validated - User is logged in');
        }
    }

    // ==================== MAIN INITIALIZATION ====================
    async function initializePanel() {
        if (window.location.href.includes('payment.ivacbd.com')) {
            loadConfig();
            loadAppData();

            const sessionLoaded = loadSession();

            document.body.appendChild(panel);
            panel.style.display = 'block';

            setupSessionMonitor();

            detectClientIP().then(ip => {
                console.log(`[INIT] IP detection completed: ${ip}`);
            });

            setTimeout(() => {
                updateTokensFromResponse(null, null);
                const isLoggedIn = validateSession();

                if (isLoggedIn) {
                    serverData.session_data.is_logged_in = true;
                    setStatus('✅ Auto-detected: Logged in with token authentication');
                    updatePanelLoginState(true);
                } else if (sessionLoaded) {
                    setStatus('Session loaded but requires re-authentication');
                } else {
                    setStatus('Ready - Enhanced API response handling active');
                }
            }, 1500);

            makeDraggable(panel, header);

            console.log('[INIT] Ultimate Panel v14.2 initialized with enhanced API response handling');
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializePanel);
    } else {
        initializePanel();
    }

})();