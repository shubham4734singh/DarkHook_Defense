// DarkHook Defense API Service
// API configuration for connecting to backend

// Priority order:
// 1. VITE_API_BASE_URL environment variable (if set)
// 2. Localhost for development
// 3. Production URL only if explicitly deployed and URL is set
const getApiBaseUrl = (): string => {
  // Check for explicit environment variable (highest priority)
  if (import.meta.env.VITE_API_BASE_URL) {
    console.log('📌 Using VITE_API_BASE_URL:', import.meta.env.VITE_API_BASE_URL);
    return import.meta.env.VITE_API_BASE_URL;
  }

  // For local development, always use localhost:8000
  // unless absolutely in production with Render deployed
  const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  
  if (isLocalhost) {
    console.log('🏠 Local development detected, using localhost:8000');
    return 'http://localhost:8000';
  }

  // Only use production URL if we're on the production domain
  if (window.location.hostname.includes('darkhook') || window.location.hostname.includes('render')) {
    console.log('🚀 Production environment detected');
    return 'https://darkhook-defense.onrender.com';
  }

  // Fallback to localhost
  console.log('⚠️ Using fallback: localhost:8000');
  return 'http://localhost:8000';
};

const API_BASE_URL = getApiBaseUrl();

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  name: string;
  email: string;
  password: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
}

export interface UserResponse {
  name: string;
  email: string;
}

export interface EmailOtpRequestBody {
  email: string;
}

export interface EmailOtpVerifyBody {
  email: string;
  otp: string;
}

export interface MessageResponse {
  message: string;
}

export interface ScoreBreakdownItem {
  finding_type: string;
  score: number;
}

export interface DocumentScanResult {
  fileName: string;
  fileSize: string;
  fileHash: string;
  riskScore: number;
  verdict: string;
  scanTime: number;
  totalFindings: number;
  findings: string[];
  scoreBreakdown: ScoreBreakdownItem[];
  details: string[];
}

class ApiService {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
    console.log(`🔧 API Service initialized with baseUrl: ${baseUrl}`);
  }

  private getAuthHeaders(): HeadersInit {
    const token = localStorage.getItem('darkhook_token');
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  }

  async login(email: string, password: string): Promise<AuthResponse> {
    const response = await fetch(`${this.baseUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(error.detail || 'Login failed');
    }

    return response.json();
  }

  async register(name: string, email: string, password: string): Promise<AuthResponse> {
    const response = await fetch(`${this.baseUrl}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ name, email, password }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Registration failed' }));
      throw new Error(error.detail || 'Registration failed');
    }

    return response.json();
  }

  async getCurrentUser(): Promise<UserResponse | null> {
    try {
      const response = await fetch(`${this.baseUrl}/auth/me`, {
        method: 'GET',
        headers: this.getAuthHeaders(),
      });

      if (!response.ok) {
        // Return null instead of throwing - allows app to continue
        return null;
      }

      return response.json();
    } catch (error) {
      // Network error or server down - return null
      console.warn('Failed to get current user:', error);
      return null;
    }
  }

  async requestEmailOtp(email: string): Promise<MessageResponse> {
    const response = await fetch(`${this.baseUrl}/auth/email-otp/request`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email } satisfies EmailOtpRequestBody),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'OTP request failed' }));
      throw new Error(error.detail || 'OTP request failed');
    }

    return response.json();
  }

  async verifyEmailOtp(email: string, otp: string): Promise<MessageResponse> {
    const response = await fetch(`${this.baseUrl}/auth/email-otp/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, otp } satisfies EmailOtpVerifyBody),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'OTP verification failed' }));
      throw new Error(error.detail || 'OTP verification failed');
    }

    return response.json();
  }

  async scanDocument(file: File): Promise<DocumentScanResult> {
    const fullUrl = `${this.baseUrl}/scan/document`;

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(fullUrl, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Document scan failed' }));
        throw new Error(error.detail || `HTTP ${response.status}: Document scan failed`);
      }

      return response.json();
    } catch (error) {
      console.error('Document scan failed:', error);
      throw error;
    }
  }

  async scanUrl(url: string): Promise<any> {
    const fullUrl = `${this.baseUrl}/scan/url`;
    
    console.log(`\n📡 === API CALL START ===`);
    console.log(`Base URL: ${this.baseUrl}`);
    console.log(`Full URL: ${fullUrl}`);
    console.log(`Method: POST`);
    console.log(`Headers: Content-Type: application/json`);
    console.log(`Payload: ${JSON.stringify({ url })}`);
    
    try {
      console.log(`⏳ Fetching...`);
      const response = await fetch(fullUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      console.log(`📊 Response received:`);
      console.log(`  Status: ${response.status} ${response.statusText}`);
      console.log(`  Content-Type: ${response.headers.get('content-type')}`);

      if (!response.ok) {
        const errorText = await response.text();
        console.error(`❌ Response NOT OK (status ${response.status})`);
        console.error(`  Response body: ${errorText}`);
        throw new Error(errorText.includes('detail') ? 
          `API Error ${response.status}: ${errorText}` : 
          `HTTP ${response.status}: ${errorText.substring(0, 100)}`);
      }

      const result = await response.json();
      console.log(`✅ === API CALL SUCCESS ===\n`);
      return result;
    } catch (error) {
      console.error(`❌ === API CALL FAILED ===\n`);
      console.error(`Error:`, error);
      throw error;
    }
  }
}

export const api = new ApiService(API_BASE_URL);
