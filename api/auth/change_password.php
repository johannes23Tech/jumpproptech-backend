const API_URL = 'https://jumpproptech-api.onrender.com/api'; 

const getHeaders = () => {
  const token = localStorage.getItem('token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {})
  };
};

const handleResponse = async (res: Response) => {
  const text = await res.text();
  try {
    const data = JSON.parse(text);
    if (!res.ok) throw new Error(data.message || 'Server error');
    return data;
  } catch (err) {
    throw new Error(`Backend returned invalid JSON. Raw output: ${text.substring(0, 100)}...`);
  }
};

export const api = {
  // --- AUTHENTICATION ---
  login: async (email: string, password: string) => {
    const res = await fetch(`${API_URL}/auth/login.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    return handleResponse(res);
  },

  register: async (userData: any) => {
    const res = await fetch(`${API_URL}/auth/register.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData),
    });
    return handleResponse(res);
  },

  forgotPassword: async (email: string) => {
    const res = await fetch(`${API_URL}/auth/forgot_password.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    return handleResponse(res);
  },

  resetPassword: async (data: any) => {
    const res = await fetch(`${API_URL}/auth/reset_password.php`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  changePassword: async (data: { currentPassword: string, newPassword: string }) => {
    const res = await fetch(`${API_URL}/auth/change_password.php`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse(res);
  },

  // --- DASHBOARD ---
  getDashboardStats: async () => {
    const res = await fetch(`${API_URL}/dashboard.php`, { headers: getHeaders() });
    return handleResponse(res);
  },

  // --- PROPERTIES ---
  getProperties: async () => {
    const res = await fetch(`${API_URL}/properties.php`, { headers: getHeaders() });
    return handleResponse(res);
  },

  createProperty: async (propertyData: any) => {
    const res = await fetch(`${API_URL}/properties.php`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(propertyData),
    });
    return handleResponse(res);
  },

  // --- UNITS / ROOMS ---
  getUnits: async () => {
    const res = await fetch(`${API_URL}/units.php`, { headers: getHeaders() });
    return handleResponse(res);
  },

  createUnit: async (unitData: any) => {
    const res = await fetch(`${API_URL}/units.php`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(unitData),
    });
    return handleResponse(res);
  },

  // --- TENANTS ---
  getTenants: async () => {
    const res = await fetch(`${API_URL}/tenants.php`, { headers: getHeaders() });
    return handleResponse(res);
  },

  createTenant: async (data: any) => {
    const res = await fetch(`${API_URL}/tenants.php`, { 
      method: 'POST', 
      headers: getHeaders(), 
      body: JSON.stringify(data) 
    });
    return handleResponse(res);
  },

  // --- TENANT DATA ---
  getTenantData: async () => {
    const res = await fetch(`${API_URL}/tenant_data.php`, { headers: getHeaders() });
    return handleResponse(res);
  },

  getTenantProfile: async () => {
    const res = await fetch(`${API_URL}/tenant_profile.php`, { headers: getHeaders() });
    return handleResponse(res);
  },

  updateTenantProfile: async (data: any) => {
    const res = await fetch(`${API_URL}/tenant_profile.php`, { 
      method: 'POST', 
      headers: getHeaders(), 
      body: JSON.stringify(data) 
    });
    return handleResponse(res);
  },

  // --- MAINTENANCE ---
  getMaintenanceData: async () => {
    const res = await fetch(`${API_URL}/maintenance.php`, { headers: getHeaders() });
    return handleResponse(res);
  },

  logMaintenance: async (data: any) => {
    const res = await fetch(`${API_URL}/maintenance.php`, { 
      method: 'POST', 
      headers: getHeaders(), 
      body: JSON.stringify(data) 
    });
    return handleResponse(res);
  },

  assignContractor: async (data: any) => {
    const res = await fetch(`${API_URL}/maintenance.php`, { 
      method: 'POST', 
      headers: getHeaders(), 
      body: JSON.stringify(data) 
    });
    return handleResponse(res);
  },

  resolveMaintenance: async (ticket_id: number) => {
    const res = await fetch(`${API_URL}/maintenance.php`, { 
      method: 'POST', 
      headers: getHeaders(), 
      body: JSON.stringify({ ticket_id, status: 'Resolved' }) 
    });
    return handleResponse(res);
  },

  addContractor: async (data: { name: string, trade: string, phone: string }) => {
    const res = await fetch(`${API_URL}/maintenance.php`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ ...data, action: 'add_contractor' }),
    });
    return handleResponse(res);
  },

  // --- RENT & RECEIPTS ---
  getRentRecords: async () => {
    const res = await fetch(`${API_URL}/rent.php`, { headers: getHeaders() });
    return handleResponse(res);
  },

  payRent: async (data: any) => {
    const res = await fetch(`${API_URL}/rent.php`, { 
      method: 'POST', 
      headers: getHeaders(), 
      body: JSON.stringify(data) 
    });
    return handleResponse(res);
  },

  sendReceiptEmail: async (data: { email: string, receipt_number: string }) => {
    const res = await fetch(`${API_URL}/send_receipt.php`, { 
      method: 'POST', 
      headers: getHeaders(), 
      body: JSON.stringify(data) 
    });
    return handleResponse(res);
  },

  // --- MESSAGING ---
  getMessages: async (tenantId?: number) => {
    const url = tenantId ? `${API_URL}/messages.php?tenant_id=${tenantId}` : `${API_URL}/messages.php`;
    const res = await fetch(url, { headers: getHeaders() });
    return handleResponse(res);
  },

  sendMessage: async (data: { receiver_id: number, tenant_id: number, message: string }) => {
    const res = await fetch(`${API_URL}/messages.php`, { 
      method: 'POST', 
      headers: getHeaders(), 
      body: JSON.stringify(data) 
    });
    return handleResponse(res);
  },

  // --- CLOUDINARY IMAGE UPLOAD ---
  uploadImage: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    
    const cloudName = 'mvy6f66e'; 
    const uploadPreset = 'jumpproptech_preset'; 

    formData.append('upload_preset', uploadPreset);

    const res = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/upload`, {
      method: 'POST',
      body: formData,
    });
    
    if (!res.ok) throw new Error('Failed to upload image to Cloudinary');
    const data = await res.json();
    return data.secure_url; 
  },

  // --- LOCAL STORAGE ---
  getUser: () => {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
  }
};