// Firebase SDK imports
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.2.0/firebase-app.js";
import {
    getAuth,
    signInWithEmailAndPassword,
    createUserWithEmailAndPassword,
    signOut,
    onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/11.2.0/firebase-auth.js";
import {
    getFirestore,
    collection,
    doc,
    addDoc,
    updateDoc,
    deleteDoc,
    getDocs,
    getDoc,
    query,
    where,
    orderBy,
    onSnapshot,
    serverTimestamp
} from "https://www.gstatic.com/firebasejs/11.2.0/firebase-firestore.js";

// Firebase configuration (same as CRM/HRMS)
const firebaseConfig = {
    apiKey: "AIzaSyACCpl5f7g34Fs0eMxUguBuGE80SuKZCIA",
    authDomain: "hrms-326ad.firebaseapp.com",
    projectId: "hrms-326ad",
    storageBucket: "hrms-326ad.firebasestorage.app",
    messagingSenderId: "813107687048",
    appId: "1:813107687048:web:2d3c2fff54a65285ba793d",
    measurementId: "G-HXGFCBV64Q"
};

// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig);
const auth = getAuth(firebaseApp);
const db = getFirestore(firebaseApp);

// Menu structure for HRMS & CRM permissions
const defaultMenuStructure = [
    // CRM Modules
    { id: 'crm', name: 'CRM', isCategory: true },
    { id: 'crm_dashboard', name: 'Dashboard', parent: 'crm' },
    { id: 'prospect_management', name: 'Prospect Management', parent: 'crm' },
    { id: 'lead_management', name: 'Lead Management', parent: 'crm' },
    { id: 'whatsapp_templates', name: 'WhatsApp Templates', parent: 'crm' },
    { id: 'analytics', name: 'Analytics', parent: 'crm' },
    { id: 'data_management', name: 'Data Management', parent: 'crm' },
    { id: 'team_management', name: 'Team Management', parent: 'crm' },
];

// Application Class
class AccessControlApp {
    constructor() {
        this.users = [];
        this.roles = [];
        this.emails = [];
        this.currentUser = null;
        this.selectedRole = null;
        this.currentUserFilter = 'active';
        this.currentDesignationFilter = '';
        this.menuStructure = defaultMenuStructure;
        this.passwordVisibility = new Set();
        this.init();
    }

    init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setup());
        } else {
            this.setup();
        }
    }

    setup() {
        this.cacheDOM();

        const roleSelect = this.userForm.querySelector('[name="role"]');
        if (roleSelect) {
            roleSelect.addEventListener('change', (e) => this.fetchRolePermissions(e.target.value));
        }

        this.bindEvents();
        this.initializeAuth();

        // Initialize Feather icons
        if (typeof feather !== 'undefined') {
            feather.replace();
        }
    }

    cacheDOM() {
        // Pages
        this.loginPage = document.getElementById('login-page');
        this.appContainer = document.getElementById('app');

        // Login elements
        this.loginForm = document.getElementById('login-form');
        this.emailInput = document.getElementById('email');
        this.passwordInput = document.getElementById('password');

        // Header elements
        this.pageTitle = document.querySelector('.page-title');
        this.userName = document.querySelector('.user-name');
        this.logoutBtn = document.getElementById('logout-btn');
        this.sidebarToggle = document.getElementById('sidebar-toggle');
        this.sidebar = document.getElementById('sidebar');

        // Navigation
        this.navItems = document.querySelectorAll('.nav-item');
        this.pages = document.querySelectorAll('.page');

        // User Management
        this.statusTabs = document.querySelectorAll('.status-tab');
        this.userSearch = document.getElementById('user-search');
        this.usersTbody = document.getElementById('users-tbody');
        // User buttons & Filters
        this.addUserBtn = document.getElementById('add-user-btn');
        this.refreshUsersBtn = document.getElementById('refresh-users-btn');
        this.exportUsersBtn = document.getElementById('export-users-btn');
        this.designationFilter = document.getElementById('user-designation-filter');

        // User Modal
        this.userModal = document.getElementById('user-modal');
        this.userModalTitle = document.getElementById('user-modal-title');
        this.userForm = document.getElementById('user-form');

        // Role Management
        this.rolesTbody = document.getElementById('roles-tbody');
        this.addRoleBtn = document.getElementById('add-role-btn');
        this.editRoleBtn = document.getElementById('edit-role-btn');
        this.deleteRoleBtn = document.getElementById('delete-role-btn');
        this.closeRoleBtn = document.getElementById('close-role-btn');

        // Role Modal
        this.roleModal = document.getElementById('role-modal');
        this.roleModalTitle = document.getElementById('role-modal-title');
        this.roleForm = document.getElementById('role-form');

        // Capabilities
        this.capabilitiesTbody = document.getElementById('capabilities-tbody');
        this.updateCapabilitiesBtn = document.getElementById('update-capabilities-btn');
        this.exportExcelBtn = document.getElementById('export-excel-btn');
        this.checkAllAdd = document.getElementById('check-all-add');
        this.checkAllEdit = document.getElementById('check-all-edit');
        this.checkAllDelete = document.getElementById('check-all-delete');
        this.checkAllView = document.getElementById('check-all-view');

        // Email Management
        this.emailsTbody = document.getElementById('emails-tbody');
        this.addEmailBtn = document.getElementById('add-email-btn');
        this.emailModal = document.getElementById('email-modal');
        this.emailForm = document.getElementById('email-form');
        this.emailModalTitle = document.getElementById('email-modal-title');
        this.emailSearch = document.getElementById('email-search');

        // Toast
        this.toast = document.getElementById('toast');
    }

    bindEvents() {
        // Login
        this.loginForm?.addEventListener('submit', (e) => this.handleLogin(e));
        this.logoutBtn?.addEventListener('click', () => this.handleLogout());

        // Sidebar toggle (mobile)
        this.sidebarToggle?.addEventListener('click', () => {
            this.sidebar?.classList.toggle('open');
        });

        // Navigation
        this.navItems.forEach(item => {
            item.addEventListener('click', (e) => this.handleNavigation(e));
        });

        // Status tabs
        this.statusTabs.forEach(tab => {
            tab.addEventListener('click', (e) => this.handleStatusTabClick(e));
        });

        // User search
        this.userSearch?.addEventListener('input', (e) => this.handleUserSearch(e.target.value));

        // User buttons
        // User buttons & Filters
        this.addUserBtn?.addEventListener('click', () => this.openUserModal());
        this.refreshUsersBtn?.addEventListener('click', () => this.loadUsers());
        
        this.exportUsersBtn?.addEventListener('click', () => this.exportUsersToCSV());
        this.designationFilter?.addEventListener('change', (e) => {
            this.currentDesignationFilter = e.target.value;
            this.renderUsersTable(this.userSearch?.value || '');
        });

        // User form
        this.userForm?.addEventListener('submit', (e) => this.handleUserSubmit(e));

        // Role buttons
        this.addRoleBtn?.addEventListener('click', () => this.openRoleModal());
        this.editRoleBtn?.addEventListener('click', () => this.editSelectedRole());
        this.deleteRoleBtn?.addEventListener('click', () => this.deleteSelectedRole());
        this.closeRoleBtn?.addEventListener('click', () => this.deselectRole());

        // Role form
        this.roleForm?.addEventListener('submit', (e) => this.handleRoleSubmit(e));

        // Capabilities
        this.updateCapabilitiesBtn?.addEventListener('click', () => this.updateCapabilities());
        this.exportExcelBtn?.addEventListener('click', () => this.exportToExcel());

        // Check all checkboxes
        this.checkAllAdd?.addEventListener('change', (e) => this.toggleAllPermissions('add', e.target.checked));
        this.checkAllEdit?.addEventListener('change', (e) => this.toggleAllPermissions('edit', e.target.checked));
        this.checkAllDelete?.addEventListener('change', (e) => this.toggleAllPermissions('delete', e.target.checked));
        this.checkAllView?.addEventListener('change', (e) => this.toggleAllPermissions('view', e.target.checked));

        // Email Management
        this.addEmailBtn?.addEventListener('click', () => this.openEmailModal());
        this.emailForm?.addEventListener('submit', (e) => this.handleEmailSubmit(e));
        this.emailSearch?.addEventListener('input', (e) => this.renderEmailsTable(e.target.value));

        // Modal close buttons
        document.querySelectorAll('.modal-close, .modal-close-btn').forEach(btn => {
            btn.addEventListener('click', () => this.closeAllModals());
        });

        // Close modal on backdrop click
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.closeAllModals();
            });
        });
    }

    initializeAuth() {
        onAuthStateChanged(auth, (user) => {
            if (user) {
                this.currentUser = user;
                this.showApp();
                this.loadData();
            } else {
                this.showLogin();
                // HARDCODED AUTO-LOGIN: Attempt login with specific credentials once
                if (!this._attemptedAutoLogin) {
                    this._attemptedAutoLogin = true;
                    console.log("Attempting hardcoded auto-login...");
                    signInWithEmailAndPassword(auth, "nextgenudaan@gmail.com", "Anchan@4746")
                        .then(() => {
                            console.log("Auto-login success!");
                            this.showToast('Auto-login successful!', 'success');
                        })
                        .catch(err => {
                            console.error("Auto-login failed:", err);
                        });
                }
            }
        });

        // Initialize Secondary App for User Creation (still needed for creating other users)
        try {
            const secondaryApp = initializeApp(firebaseConfig, "Secondary");
            this.secondaryAuth = getAuth(secondaryApp);
        } catch (e) {
            console.warn("Secondary app might already be initialized:", e);
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        const email = this.emailInput.value.trim();
        const password = this.passwordInput.value;

        const submitBtn = this.loginForm.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span>Signing in...</span>';

        try {
            await signInWithEmailAndPassword(auth, email, password);
            this.showToast('Login successful!', 'success');
        } catch (error) {
            console.error('Login error:', error);
            this.showToast('Invalid email or password', 'error');
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<span>Sign in</span><i data-feather="arrow-right" class="btn-icon"></i>';
            if (typeof feather !== 'undefined') feather.replace();
        }
    }

    async handleLogout() {
        try {
            await signOut(auth);
            this.showToast('Logged out successfully', 'success');
        } catch (error) {
            console.error('Logout error:', error);
            this.showToast('Error logging out', 'error');
        }
    }

    showLogin() {
        this.loginPage?.classList.remove('hidden');
        this.appContainer?.classList.add('hidden');
    }

    showApp() {
        this.loginPage?.classList.add('hidden');
        this.appContainer?.classList.remove('hidden');
        if (this.currentUser) {
            this.userName.textContent = this.currentUser.email.split('@')[0];
        }
        if (typeof feather !== 'undefined') feather.replace();
    }

    // ==================== DATA LOADING ====================
    async loadData() {
        // Load users first to avoid race condition in email assignment rendering
        await this.loadUsers();
        await Promise.all([
            this.loadRoles(),
            this.loadEmails()
        ]);
        this.renderCapabilitiesTable();
    }

    async loadUsers() {
        try {
            // Load users from HRMS employees collection
            const employeesSnapshot = await getDocs(collection(db, 'employees'));
            const employees = employeesSnapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data()
            }));

            // Load access control data (HRMS/CRM permissions per user)
            const accessSnapshot = await getDocs(collection(db, 'userAccess'));
            const accessMap = {};
            const duplicates = [];

            accessSnapshot.docs.forEach(doc => {
                const data = doc.data();
                const empId = data.employeeId;
                
                if (accessMap[empId]) {
                    duplicates.push({ empId, existing: accessMap[empId].accessId, new: doc.id });
                }

                accessMap[empId] = {
                    accessId: doc.id,
                    ...data
                };
            });

            if (duplicates.length > 0) {
                // Duplicates found but we will handle them silently for now
            }

            // Merge employees with access data
            this.users = employees.map(emp => ({
                ...emp,
                role: accessMap[emp.id]?.role || 'User',

                hasCRMAccess: accessMap[emp.id]?.hasCRMAccess || false,
                accessId: accessMap[emp.id]?.accessId || null
            }));

            this.renderUsersTable();
            this.populateRoleDropdown();
            this.populateUserDropdown();
        } catch (error) {
            console.error('Error loading users:', error);
            this.showToast('Error loading users', 'error');
        }
    }

    async loadRoles() {
        try {
            const querySnapshot = await getDocs(collection(db, 'accessRoles'));
            this.roles = querySnapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data()
            }));
            this.renderRolesTable();
            this.populateRoleDropdown();
        } catch (error) {
            console.error('Error loading roles:', error);
            this.showToast('Error loading roles', 'error');
        }
    }

    async loadEmails() {
        try {
            const querySnapshot = await getDocs(collection(db, 'emailCredentials'));
            this.emails = querySnapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data()
            }));
            this.renderEmailsTable();
        } catch (error) {
            console.error('Error loading emails:', error);
        }
    }

    // ==================== NAVIGATION ====================
    handleNavigation(e) {
        e.preventDefault();
        const item = e.currentTarget;
        const page = item.dataset.page;

        // Update active nav item
        this.navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');

        // Update page title
        const titles = {
            'users': 'User Management',
            'roles': 'Role & Permissions',
            'emails': 'Email Management'
        };
        this.pageTitle.textContent = titles[page] || 'Dashboard';

        // Show corresponding page
        this.pages.forEach(p => p.classList.remove('active'));
        document.getElementById(`${page}-page`)?.classList.add('active');

        // Close sidebar on mobile
        this.sidebar?.classList.remove('open');
    }

    // ==================== USER MANAGEMENT ====================
    handleStatusTabClick(e) {
        const tab = e.currentTarget;
        const status = tab.dataset.status;

        this.statusTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        this.currentUserFilter = status;
        this.renderUsersTable();
    }

    handleUserSearch(searchTerm) {
        this.renderUsersTable(searchTerm);
    }

    renderUsersTable(searchTerm = '') {
        if (!this.usersTbody) return;

        const filteredUsers = this.users.filter(user => {
            // Map HRMS status to our filter
            const userStatus = (user.status || 'Active').toLowerCase() === 'active' ? 'active' : 'inactive';
            const matchesStatus = userStatus === this.currentUserFilter;
            
            // Designation Filter
            const matchesDesignation = this.currentDesignationFilter === '' || 
                                     user.designation === this.currentDesignationFilter;

            const matchesSearch = searchTerm === '' ||
                user.fullName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                user.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                user.empCode?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                user.mobile?.includes(searchTerm);
                
            return matchesStatus && matchesDesignation && matchesSearch;
        });

        if (filteredUsers.length === 0) {
            this.usersTbody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align: center; padding: 40px; color: var(--color-text-secondary);">
                        No users found
                    </td>
                </tr>
            `;
            return;
        }

        this.usersTbody.innerHTML = filteredUsers.map(user => `
            <tr>
                <td>
                    <div class="user-info">
                        <div>
                            <div class="user-name">${this.escapeHtml(user.fullName || user.username)}</div>
                            <div class="user-email-sm">${this.escapeHtml(user.empCode || '')}</div>
                        </div>
                    </div>
                </td>
                <td>${this.escapeHtml(user.designation || '-')}</td>
                <td>${this.escapeHtml(user.mobile || '-')}</td>
                <td>${this.escapeHtml(user.email)}</td>
                <td><span class="badge ${user.role === 'Admin' ? 'badge--primary' : 'badge--secondary'}">${user.role || 'User'}</span></td>
                <td>
                    <span class="status-indicator ${user.hasCRMAccess ? 'status-active' : 'status-inactive'}">
                        ${user.hasCRMAccess ? 'Enabled' : 'Disabled'}
                    </span>
                </td>
                <td>
                    <div class="action-buttons-sm">
                        <button class="action-btn edit" onclick="app.editUserAccess('${user.id}')" title="Edit Access">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                        </button>

                        <button class="action-btn toggle ${user.hasCRMAccess ? 'active' : ''}" onclick="app.toggleAccess('${user.id}', 'crm')" title="Toggle CRM">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    exportUsersToCSV() {
        if (!this.users || this.users.length === 0) {
            this.showToast('No users to export', 'info');
            return;
        }

        const headers = ['Distributor ID', 'Full Name', 'Father Name', 'DOB', 'Mobile', 'Email', 'Location', 'DOJ', 'Designation', 'Access Role', 'Status'];
        
        const rows = this.users.map(user => [
            user.empCode || '',
            user.fullName || user.username || '',
            user.fatherName || '',
            user.dob || '',
            user.mobile || '',
            user.email || '',
            user.location || '',
            user.doj || '',
            user.designation || '',
            user.role || 'User',
            user.status || 'Active'
        ]);

        const csvContent = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        
        link.setAttribute('href', url);
        link.setAttribute('download', `employees_export_${new Date().toISOString().slice(0,10)}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    openUserModal(userId = null) {
        this.populateRoleDropdown(); // Ensure roles are fresh
        const user = userId ? this.users.find(u => u.id === userId) : null;

        this.userModalTitle.textContent = user ? 'Edit User Access' : 'Grant User Access';
        this.userForm.reset();
        this.userForm.querySelector('[name="user-id"]').value = userId || '';

        if (user) {
            this.userForm.querySelector('[name="username"]').value = user.fullName || user.username || '';
            this.userForm.querySelector('[name="email"]').value = user.email || '';
            
            // Populate new HRMS fields
            this.setInputValue('empCode', user.empCode);
            this.setInputValue('fatherName', user.fatherName);
            this.setInputValue('dob', user.dob);
            this.setInputValue('mobile', user.mobile);
            this.setInputValue('location', user.location);
            this.setInputValue('doj', user.doj);
            this.setInputValue('designation', user.designation);
            this.setInputValue('dol', user.dol);

            this.userForm.querySelector('[name="password"]').value = '';
            this.userForm.querySelector('[name="password"]').required = false;
            this.userForm.querySelector('[name="role"]').value = user.role || 'User';

            this.userForm.querySelector('[name="hasCRMAccess"]').checked = user.hasCRMAccess || false;

            // Fetch and show permissions for the selected role
            this.fetchRolePermissions(user.role || 'User');
        } else {
            this.userForm.querySelector('[name="password"]').required = true;
            this.userForm.querySelector('[name="role"]').value = 'User';
            this.fetchRolePermissions('User');
        }

        this.userModal.classList.remove('hidden');
        if (typeof feather !== 'undefined') feather.replace();
    }
    
    setInputValue(name, value) {
        const input = this.userForm.querySelector(`[name="${name}"]`);
        if (input) input.value = value || '';
    }

    editUserAccess(userId) {
        this.openUserModal(userId);
    }

    async fetchRolePermissions(roleName) {
        if (!roleName) {
            const container = document.getElementById('role-permissions-preview');
            if (container) container.innerHTML = '<p class="info-text">Select a role to see permissions</p>';
            return;
        }

        try {
            const role = this.roles.find(r => r.name === roleName);
            const container = document.getElementById('role-permissions-preview');
            if (!container) return;

            if (role && role.permissions?.crm) {
                const perms = role.permissions.crm;
                let html = '<div class="permissions-preview-grid">';

                this.menuStructure.forEach(menu => {
                    if (!menu.isCategory) {
                        const p = perms[menu.id] || { view: false };
                        if (p.view || p.add || p.edit || p.delete) {
                            html += `
                                <div class="perm-preview-item">
                                    <span class="perm-menu-name">${menu.name}:</span>
                                    <span class="perm-tags">
                                        ${p.view ? '<span class="perm-tag">View</span>' : ''}
                                        ${p.add ? '<span class="perm-tag">Add</span>' : ''}
                                        ${p.edit ? '<span class="perm-tag">Edit</span>' : ''}
                                        ${p.delete ? '<span class="perm-tag">Delete</span>' : ''}
                                    </span>
                                </div>
                            `;
                        }
                    }
                });

                html += '</div>';
                container.innerHTML = html || '<p class="info-text">No CRM permissions defined for this role.</p>';
            } else {
                container.innerHTML = '<p class="info-text">No specific permissions found for this role.</p>';
            }
        } catch (error) {
            console.error('Error fetching role permissions:', error);
        }
    }

    async handleUserSubmit(e) {
        e.preventDefault();

        const formData = new FormData(this.userForm);
        let userId = formData.get('user-id');
        const email = formData.get('email');
        const password = formData.get('password');
        const username = formData.get('username');

        // Feature: Create Auth User if password is provided
        if (password && password.length >= 6) {
            // Ensure secondary auth is initialized
            if (!this.secondaryAuth) {
                try {
                    const secondaryApp = initializeApp(firebaseConfig, "Secondary");
                    this.secondaryAuth = getAuth(secondaryApp);
                    console.log('Secondary auth initialized during user creation');
                } catch (e) {
                    console.error('Failed to initialize secondary auth:', e);
                    this.showToast('Warning: Could not create auth account', 'warning');
                }
            }

            if (this.secondaryAuth) {
                try {
                    console.log(`Creating Firebase Auth account for: ${email}`);
                    const userCredential = await createUserWithEmailAndPassword(this.secondaryAuth, email, password);
                    console.log('Firebase Auth account created successfully!', userCredential.user.uid);
                    this.showToast('✅ Firebase Auth Account Created!', 'success');
                    
                    // Sign out from secondary auth to avoid conflicts
                    await signOut(this.secondaryAuth);
                } catch (err) {
                    console.error("Firebase Auth Creation Error:", err);
                    if (err.code === 'auth/email-already-in-use') {
                        console.log('Auth user already exists - this is OK');
                        this.showToast('Auth account already exists (OK)', 'info');
                    } else if (err.code === 'auth/invalid-email') {
                        this.showToast('Invalid email format', 'error');
                        console.error('Invalid email:', email);
                    } else if (err.code === 'auth/weak-password') {
                        this.showToast('Password too weak (min 6 characters)', 'error');
                    } else {
                        this.showToast('Auth Error: ' + err.message, 'error');
                    }
                    // Don't block user creation if auth fails
                }
            } else {
                console.warn("Secondary Auth not available - skipping Firebase Auth creation");
                this.showToast('Warning: Firebase Auth account not created', 'warning');
            }
        } else if (password && password.length < 6) {
            this.showToast('Password must be at least 6 characters', 'error');
            return; // Don't proceed with user creation
        }

        try {
            const dol = formData.get('dol');
            let status = 'Active';
            let hasCRMAccess = formData.get('hasCRMAccess') === 'on';

            // Auto-revoke access if leaving date is set
            if (dol) {
                status = 'Inactive';
                hasCRMAccess = false;
                // Toast to inform user of auto-action
                // this.showToast('User deactivated due to Leaving Date', 'info'); 
            }

            const employeeData = {
                fullName: username,
                email: email,
                empCode: formData.get('empCode'),
                fatherName: formData.get('fatherName'),
                dob: formData.get('dob'),
                mobile: formData.get('mobile'),
                location: formData.get('location'),
                doj: formData.get('doj'),
                designation: formData.get('designation'),
                dol: dol,
                status: status,
                updatedAt: serverTimestamp()
            };

            // If new user (no userId), create Employee record first
            if (!userId) {
                employeeData.createdAt = serverTimestamp();
                const empRef = await addDoc(collection(db, 'employees'), employeeData);
                userId = empRef.id; // Use the new employee ID
                this.showToast('Employee record created!', 'success');
            } else {
                // Update existing employee details
                await updateDoc(doc(db, 'employees', userId), employeeData);
            }

            const accessData = {
                employeeId: userId,
                role: formData.get('role'),
                hasCRMAccess: hasCRMAccess,
                updatedAt: serverTimestamp()
            };

            const user = this.users.find(u => u.id === userId);

            if (user?.accessId) {
                // Update existing access record
                await updateDoc(doc(db, 'userAccess', user.accessId), accessData);
                this.showToast('User access updated successfully!', 'success');
            } else { // Handle case where user exists but access record doesn't, OR we just created the user
                // Check if access record exists (double check)
                const q = query(collection(db, 'userAccess'), where('employeeId', '==', userId));
                const querySnapshot = await getDocs(q);
                
                if (!querySnapshot.empty) {
                     const accessId = querySnapshot.docs[0].id;
                     await updateDoc(doc(db, 'userAccess', accessId), accessData);
                } else {
                    // Create new access record
                    accessData.createdAt = serverTimestamp();
                    await addDoc(collection(db, 'userAccess'), accessData);
                }
                this.showToast('User permissions assigned!', 'success');
            }

            this.closeAllModals();
            await this.loadUsers();
        } catch (error) {
            console.error('Error saving user access:', error);
            this.showToast('Error saving user access: ' + error.message, 'error');
        }
    }

    async toggleAccess(userId, accessType) {
        if (accessType !== 'crm') return;

        const user = this.users.find(u => u.id === userId);
        if (!user) return;

        const newValue = !user.hasCRMAccess;

        try {
            if (user.accessId) {
                await updateDoc(doc(db, 'userAccess', user.accessId), {
                    hasCRMAccess: newValue,
                    updatedAt: serverTimestamp()
                });
            } else {
                // Create new access record
                await addDoc(collection(db, 'userAccess'), {
                    employeeId: userId,
                    role: 'User',
                    hasCRMAccess: newValue,
                    createdAt: serverTimestamp(),
                    updatedAt: serverTimestamp()
                });
            }

            this.showToast(`CRM access ${newValue ? 'granted' : 'revoked'}!`, 'success');
            await this.loadUsers();
        } catch (error) {
            console.error('Error toggling access:', error);
            this.showToast('Error updating access', 'error');
        }
    }

    populateRoleDropdown() {
        const roleSelect = this.userForm?.querySelector('[name="role"]');
        if (!roleSelect) return;

        const currentValue = roleSelect.value;
        // Start with default options
        let optionsHtml = '<option value="">Select Role</option>';
        optionsHtml += '<option value="Admin">Admin</option>';
        
        // Dynamically add roles from DB
        if (this.roles && this.roles.length > 0) {
            this.roles.forEach(role => {
                // Avoid duplicating Admin if it exists in DB
                // And explicitly do NOT add 'User' unless it exists in DB (removed hardcode)
                if (role.name && role.name.toLowerCase() !== 'admin') {
                     optionsHtml += `<option value="${role.name}">${this.escapeHtml(role.name)}</option>`;
                }
            });
        }

        roleSelect.innerHTML = optionsHtml;

        if (currentValue) {
            roleSelect.value = currentValue;
        }
    }

    populateUserDropdown() {
        const userSelect = this.emailForm?.querySelector('[name="assignedTo"]');
        if (!userSelect) return;

        userSelect.innerHTML = '<option value="">Unassigned</option>';

        this.users.forEach(user => {
            const option = document.createElement('option');
            option.value = user.id;
            option.textContent = user.fullName || user.email;
            userSelect.appendChild(option);
        });
    }

    // ==================== ROLE MANAGEMENT ====================
    renderRolesTable() {
        if (!this.rolesTbody) return;

        if (this.roles.length === 0) {
            this.rolesTbody.innerHTML = `
                <tr>
                    <td colspan="2" style="text-align: center; padding: 20px; color: var(--color-text-secondary);">
                        No roles defined
                    </td>
                </tr>
            `;
            return;
        }

        this.rolesTbody.innerHTML = this.roles.map((role, index) => `
            <tr data-id="${role.id}" class="${this.selectedRole?.id === role.id ? 'selected' : ''}" onclick="app.selectRole('${role.id}')">
                <td>${index + 1}</td>
                <td>${this.escapeHtml(role.name || '')}</td>
            </tr>
        `).join('');
    }

    selectRole(roleId) {
        this.selectedRole = this.roles.find(r => r.id === roleId);
        this.renderRolesTable();
        this.renderCapabilitiesTable();
    }

    deselectRole() {
        this.selectedRole = null;
        this.renderRolesTable();
        this.renderCapabilitiesTable();
    }

    openRoleModal(roleId = null) {
        const role = roleId ? this.roles.find(r => r.id === roleId) : null;

        this.roleModalTitle.textContent = role ? 'Edit Role' : 'Add New Role';
        this.roleForm.reset();
        this.roleForm.querySelector('[name="role-id"]').value = roleId || '';

        if (role) {
            this.roleForm.querySelector('[name="roleName"]').value = role.name || '';
        }

        this.roleModal.classList.remove('hidden');
        if (typeof feather !== 'undefined') feather.replace();
    }

    editSelectedRole() {
        if (!this.selectedRole) {
            this.showToast('Please select a role first', 'error');
            return;
        }
        this.openRoleModal(this.selectedRole.id);
    }

    async handleRoleSubmit(e) {
        e.preventDefault();

        const formData = new FormData(this.roleForm);
        const roleId = formData.get('role-id');
        const roleName = formData.get('roleName');

        // Initialize default permissions for new roles
        const defaultPermissions = { crm: {} };
        this.menuStructure.forEach(menu => {
            if (!menu.isCategory) {
                // Default to true for view to avoid "invisible" initial state
                defaultPermissions.crm[menu.id] = { add: false, edit: false, delete: false, view: true };
            }
        });

        try {
            if (roleId) {
                // Update existing role
                await updateDoc(doc(db, 'accessRoles', roleId), {
                    name: roleName,
                    updatedAt: serverTimestamp()
                });
                this.showToast('Role updated successfully!', 'success');
            } else {
                // Create new role
                await addDoc(collection(db, 'accessRoles'), {
                    name: roleName,
                    permissions: defaultPermissions,
                    createdAt: serverTimestamp(),
                    updatedAt: serverTimestamp()
                });
                this.showToast('Role created successfully!', 'success');
            }

            this.closeAllModals();
            await this.loadRoles();
        } catch (error) {
            console.error('Error saving role:', error);
            this.showToast('Error saving role', 'error');
        }
    }

    async deleteSelectedRole() {
        if (!this.selectedRole) {
            this.showToast('Please select a role first', 'error');
            return;
        }

        if (!confirm(`Are you sure you want to delete the role "${this.selectedRole.name}"?`)) return;

        try {
            await deleteDoc(doc(db, 'accessRoles', this.selectedRole.id));
            this.showToast('Role deleted successfully!', 'success');
            this.selectedRole = null;
            await this.loadRoles();
            this.renderCapabilitiesTable();
        } catch (error) {
            console.error('Error deleting role:', error);
            this.showToast('Error deleting role', 'error');
        }
    }

    // ==================== CAPABILITIES/PERMISSIONS ====================
    renderCapabilitiesTable() {
        if (!this.capabilitiesTbody) return;

        const permissions = this.selectedRole?.permissions?.crm || {};

        // Helper to check if all children of a category have a specific permission
        const isCategoryFull = (catId, pType) => {
            const children = this.menuStructure.filter(m => m.parent === catId);
            if (children.length === 0) return false;
            return children.every(child => {
                const childPerms = permissions[child.id] || {};
                return childPerms[pType] === true;
            });
        };

        this.capabilitiesTbody.innerHTML = this.menuStructure.map(menu => {
            if (menu.isCategory) {
                // Determine initial checked state for category checkboxes
                const allAdd = isCategoryFull(menu.id, 'add');
                const allEdit = isCategoryFull(menu.id, 'edit');
                const allDelete = isCategoryFull(menu.id, 'delete');
                const allView = isCategoryFull(menu.id, 'view');

                return `
                    <tr class="category-row">
                        <td>${this.escapeHtml(menu.name)}</td>
                        <td><input type="checkbox" data-category="${menu.id}" data-perm="add" ${allAdd ? 'checked' : ''} onchange="app.toggleCategoryPermission('${menu.id}', 'add', this.checked)"></td>
                        <td><input type="checkbox" data-category="${menu.id}" data-perm="edit" ${allEdit ? 'checked' : ''} onchange="app.toggleCategoryPermission('${menu.id}', 'edit', this.checked)"></td>
                        <td><input type="checkbox" data-category="${menu.id}" data-perm="delete" ${allDelete ? 'checked' : ''} onchange="app.toggleCategoryPermission('${menu.id}', 'delete', this.checked)"></td>
                        <td><input type="checkbox" data-category="${menu.id}" data-perm="view" ${allView ? 'checked' : ''} onchange="app.toggleCategoryPermission('${menu.id}', 'view', this.checked)"></td>
                    </tr>
                `;
            } else {
                const menuPerms = permissions[menu.id] || { add: false, edit: false, delete: false, view: false };
                return `
                    <tr class="menu-item-row" data-parent="${menu.parent}">
                        <td>${this.escapeHtml(menu.name)}</td>
                        <td><input type="checkbox" data-menu="${menu.id}" data-perm="add" ${menuPerms.add ? 'checked' : ''} ${!this.selectedRole ? 'disabled' : ''} onchange="app.handlePermissionChange('${menu.id}', 'add', this.checked)"></td>
                        <td><input type="checkbox" data-menu="${menu.id}" data-perm="edit" ${menuPerms.edit ? 'checked' : ''} ${!this.selectedRole ? 'disabled' : ''} onchange="app.handlePermissionChange('${menu.id}', 'edit', this.checked)"></td>
                        <td><input type="checkbox" data-menu="${menu.id}" data-perm="delete" ${menuPerms.delete ? 'checked' : ''} ${!this.selectedRole ? 'disabled' : ''} onchange="app.handlePermissionChange('${menu.id}', 'delete', this.checked)"></td>
                        <td><input type="checkbox" data-menu="${menu.id}" data-perm="view" ${menuPerms.view ? 'checked' : ''} ${!this.selectedRole ? 'disabled' : ''} onchange="app.handlePermissionChange('${menu.id}', 'view', this.checked)"></td>
                    </tr>
                `;
            }
        }).join('');
    }

    toggleCategoryPermission(categoryId, permType, checked) {
        const menuItems = this.menuStructure.filter(m => m.parent === categoryId);
        menuItems.forEach(menu => {
            const checkbox = document.querySelector(`input[data-menu="${menu.id}"][data-perm="${permType}"]`);
            if (checkbox) {
                checkbox.checked = checked;
                // Dispatch change event to trigger constraints (like auto-view)
                // Actually, manually handling recursion is safer to avoid loops
                
                // If checking Add/Edit/Delete, ensure View is checked
                if (checked && (permType === 'add' || permType === 'edit' || permType === 'delete')) {
                    const viewCheckbox = document.querySelector(`input[data-menu="${menu.id}"][data-perm="view"]`);
                    if (viewCheckbox) {
                        viewCheckbox.checked = true;
                        // Also update category view checkbox if all are now checked (handled by re-render or explicit update?)
                        // We will rely on schedulePermissionSave to save, and user check to update UI.
                        // To keep UI perfectly synced, we should technically update parent 'view' checkbox if all children now have 'view'.
                        this.updateCategoryCheckboxState(categoryId, 'view'); 
                    }
                }
                
                // If unchecking View, uncheck all others
                if (!checked && permType === 'view') {
                    ['add', 'edit', 'delete'].forEach(pt => {
                         const otherCb = document.querySelector(`input[data-menu="${menu.id}"][data-perm="${pt}"]`);
                         if (otherCb) otherCb.checked = false;
                    });
                    // Also update parent checkboxes for these types
                    ['add', 'edit', 'delete'].forEach(pt => this.updateCategoryCheckboxState(categoryId, pt));
                }
            }
        });
        
        // Update the category checkbox itself (redundant but safe)
        // this.schedulePermissionSave(); 
        // Better:
        this.updateCapabilities(); // Force save to sync state
    }

    // Helper to sync category checkbox with children state
    updateCategoryCheckboxState(categoryId, permType) {
        const children = this.menuStructure.filter(m => m.parent === categoryId);
        if (children.length === 0) return;

        const allChecked = children.every(child => {
            const cb = document.querySelector(`input[data-menu="${child.id}"][data-perm="${permType}"]`);
            return cb && cb.checked;
        });

        const catCheckbox = document.querySelector(`input[data-category="${categoryId}"][data-perm="${permType}"]`);
        if (catCheckbox) {
            catCheckbox.checked = allChecked;
        }
    }

    // Handle individual permission checkbox changes
    handlePermissionChange(menuId, permType, checked) {
        if (!this.selectedRole) {
            this.showToast('Please select a role first', 'error');
            return;
        }

        // Logic 1: If checking Add/Edit/Delete, must check View
        if (checked && (permType === 'add' || permType === 'edit' || permType === 'delete')) {
            const viewCheckbox = document.querySelector(`input[data-menu="${menuId}"][data-perm="view"]`);
            if (viewCheckbox && !viewCheckbox.checked) {
                viewCheckbox.checked = true;
                // Since we changed a child "view", we must update the parent "view" checkbox state
                const menu = this.menuStructure.find(m => m.id === menuId);
                if (menu?.parent) this.updateCategoryCheckboxState(menu.parent, 'view');
            }
        }

        // Logic 2: If unchecking View, must uncheck Add/Edit/Delete
        if (!checked && permType === 'view') {
            ['add', 'edit', 'delete'].forEach(pt => {
                const cb = document.querySelector(`input[data-menu="${menuId}"][data-perm="${pt}"]`);
                if (cb && cb.checked) {
                    cb.checked = false;
                    const menu = this.menuStructure.find(m => m.id === menuId);
                     if (menu?.parent) this.updateCategoryCheckboxState(menu.parent, pt);
                }
            });
        }

        // Logic 3: Update parent category checkbox state
        const menu = this.menuStructure.find(m => m.id === menuId);
        if (menu && menu.parent) {
            this.updateCategoryCheckboxState(menu.parent, permType);
        }

        // Schedule save with debounce
        this.schedulePermissionSave();
    }

    // Debounced save to prevent excessive Firebase writes
    schedulePermissionSave() {
        if (this.permissionSaveTimeout) {
            clearTimeout(this.permissionSaveTimeout);
        }
        this.permissionSaveTimeout = setTimeout(() => {
            this.updateCapabilities();
        }, 500); // Save 500ms after last change
    }

    toggleAllPermissions(permType, checked) {
        const checkboxes = document.querySelectorAll(`input[data-perm="${permType}"]:not([data-category])`);
        checkboxes.forEach(cb => {
            if (!cb.disabled) {
                cb.checked = checked;

                // Auto-check view if add/edit/delete is checked
                if (checked && (permType === 'add' || permType === 'edit' || permType === 'delete')) {
                    const menuId = cb.dataset.menu;
                    const viewCheckbox = document.querySelector(`input[data-menu="${menuId}"][data-perm="view"]`);
                    if (viewCheckbox) viewCheckbox.checked = true;
                }
            }
        });
        // Auto-save after toggling all
        this.schedulePermissionSave();
    }

    async updateCapabilities() {
        if (!this.selectedRole) {
            this.showToast('Please select a role first', 'error');
            return;
        }

        const permissions = { crm: {} };

        this.menuStructure.forEach(menu => {
            if (!menu.isCategory) {
                const addCb = document.querySelector(`input[data-menu="${menu.id}"][data-perm="add"]`);
                const editCb = document.querySelector(`input[data-menu="${menu.id}"][data-perm="edit"]`);
                const deleteCb = document.querySelector(`input[data-menu="${menu.id}"][data-perm="delete"]`);
                const viewCb = document.querySelector(`input[data-menu="${menu.id}"][data-perm="view"]`);

                permissions.crm[menu.id] = {
                    add: addCb?.checked || false,
                    edit: editCb?.checked || false,
                    delete: deleteCb?.checked || false,
                    view: viewCb?.checked || false
                };
            }
        });

        try {
            await updateDoc(doc(db, 'accessRoles', this.selectedRole.id), {
                permissions: permissions,
                updatedAt: serverTimestamp()
            });

            // Update local data
            this.selectedRole.permissions = permissions;

            this.showToast('Permissions updated successfully!', 'success');
        } catch (error) {
            console.error('Error updating permissions:', error);
            this.showToast('Error updating permissions', 'error');
        }
    }

    exportToExcel() {
        if (!this.selectedRole) {
            this.showToast('Please select a role first', 'error');
            return;
        }

        const permissions = this.selectedRole.permissions?.crm || {};

        // Create CSV content
        let csv = 'Menu,Add,Edit,Delete,View\n';

        this.menuStructure.forEach(menu => {
            if (menu.isCategory) {
                csv += `\n${menu.name},,,,\n`;
            } else {
                const perms = permissions[menu.id] || { add: false, edit: false, delete: false, view: false };
                csv += `${menu.name},${perms.add ? 'Yes' : 'No'},${perms.edit ? 'Yes' : 'No'},${perms.delete ? 'Yes' : 'No'},${perms.view ? 'Yes' : 'No'}\n`;
            }
        });

        // Download as CSV
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${this.selectedRole.name}_permissions.csv`;
        link.click();

        this.showToast('Exported successfully!', 'success');
    }

    // ==================== EMAIL MANAGEMENT ====================
    renderEmailsTable(searchTerm = '') {
        if (!this.emailsTbody) return;

        let filteredEmails = this.emails;
        if (searchTerm) {
            searchTerm = searchTerm.toLowerCase();
            filteredEmails = this.emails.filter(email => 
                (email.emailAddress || '').toLowerCase().includes(searchTerm) ||
                (email.purpose || '').toLowerCase().includes(searchTerm)
            );
        }

        if (filteredEmails.length === 0) {
            this.emailsTbody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; padding: 40px; color: var(--color-text-secondary);">
                        ${searchTerm ? 'No matching email credentials found' : 'No email credentials stored'}
                    </td>
                </tr>
            `;
            return;
        }

        this.emailsTbody.innerHTML = filteredEmails.map(email => {
            const assignedUser = this.users.find(u => u.id === email.assignedTo);
            const isPasswordVisible = this.passwordVisibility.has(email.id);
            
            return `
                <tr data-id="${email.id}">
                    <td>
                        <div class="email-cell">
                            <span>${this.escapeHtml(email.emailAddress || '')}</span>
                            <button class="icon-btn-secondary" onclick="app.copyToClipboard('${email.emailAddress}', 'Email')" title="Copy Email">
                                <i data-feather="copy"></i>
                            </button>
                        </div>
                    </td>
                    <td>
                        <div class="password-cell">
                            <span class="password-display">${isPasswordVisible ? this.escapeHtml(email.password || '') : '••••••••'}</span>
                            <div class="password-actions">
                                <button class="icon-btn-secondary" onclick="app.togglePasswordVisibility('${email.id}')" title="${isPasswordVisible ? 'Hide' : 'Show'} Password">
                                    <i data-feather="${isPasswordVisible ? 'eye-off' : 'eye'}"></i>
                                </button>
                                <button class="icon-btn-secondary" onclick="app.copyToClipboard('${email.password}', 'Password')" title="Copy Password">
                                    <i data-feather="copy"></i>
                                </button>
                            </div>
                        </div>
                    </td>
                    <td><span class="role-badge badge--${(email.purpose || 'General').toLowerCase()}">${this.escapeHtml(email.purpose || 'General')}</span></td>
                    <td>${assignedUser ? this.escapeHtml(assignedUser.fullName || assignedUser.email) : '<em>Unassigned</em>'}</td>
                    <td>
                        <div class="table-actions">
                            <button class="action-btn edit" onclick="app.editEmail('${email.id}')" title="Edit">
                                <i data-feather="edit-2"></i>
                            </button>
                            <button class="action-btn delete" onclick="app.deleteEmail('${email.id}')" title="Delete">
                                <i data-feather="trash-2"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        if (typeof feather !== 'undefined') feather.replace();
    }

    togglePasswordVisibility(emailId) {
        if (this.passwordVisibility.has(emailId)) {
            this.passwordVisibility.delete(emailId);
        } else {
            this.passwordVisibility.add(emailId);
        }
        this.renderEmailsTable(this.emailSearch?.value || '');
    }

    async copyToClipboard(text, label = 'Content') {
        try {
            await navigator.clipboard.writeText(text);
            this.showToast(`${label} copied to clipboard!`, 'success');
        } catch (err) {
            console.error('Failed to copy text: ', err);
            this.showToast('Failed to copy to clipboard', 'error');
        }
    }

    openEmailModal(emailId = null) {
        const email = emailId ? this.emails.find(e => e.id === emailId) : null;

        this.emailModalTitle.textContent = email ? 'Edit Email Credentials' : 'Add Email Credentials';
        this.emailForm.reset();
        this.emailForm.querySelector('[name="email-id"]').value = emailId || '';

        if (email) {
            this.emailForm.querySelector('[name="emailAddress"]').value = email.emailAddress || '';
            this.emailForm.querySelector('[name="emailPassword"]').value = email.password || '';
            this.emailForm.querySelector('[name="emailPassword"]').required = false;
            this.emailForm.querySelector('[name="purpose"]').value = email.purpose || '';
            this.emailForm.querySelector('[name="assignedTo"]').value = email.assignedTo || '';
            this.emailForm.querySelector('[name="notes"]').value = email.notes || '';
        } else {
            this.emailForm.querySelector('[name="emailPassword"]').required = true;
        }

        this.populateUserDropdown();
        this.emailModal.classList.remove('hidden');
        if (typeof feather !== 'undefined') feather.replace();
    }

    editEmail(emailId) {
        this.openEmailModal(emailId);
    }

    async handleEmailSubmit(e) {
        e.preventDefault();

        const formData = new FormData(this.emailForm);
        const emailId = formData.get('email-id');

        const emailData = {
            emailAddress: formData.get('emailAddress'),
            purpose: formData.get('purpose'),
            assignedTo: formData.get('assignedTo') || null,
            notes: formData.get('notes') || '',
            updatedAt: serverTimestamp()
        };

        // Only include password if provided
        const password = formData.get('emailPassword');
        if (password) {
            emailData.password = password; // In production, encrypt this
        }

        try {
            if (emailId) {
                await updateDoc(doc(db, 'emailCredentials', emailId), emailData);
                this.showToast('Email credentials updated!', 'success');
            } else {
                emailData.createdAt = serverTimestamp();
                await addDoc(collection(db, 'emailCredentials'), emailData);
                this.showToast('Email credentials saved!', 'success');
            }

            this.closeAllModals();
            await this.loadEmails();
        } catch (error) {
            console.error('Error saving email:', error);
            this.showToast('Error saving email credentials', 'error');
        }
    }

    viewEmailCredentials(emailId) {
        const email = this.emails.find(e => e.id === emailId);
        if (!email) return;

        const message = `
Email: ${email.emailAddress}
Password: ${email.password || 'Not stored'}
Purpose: ${email.purpose || 'General'}
Notes: ${email.notes || 'None'}
        `.trim();

        alert(message);
    }

    async deleteEmail(emailId) {
        if (!confirm('Are you sure you want to delete these email credentials?')) return;

        try {
            await deleteDoc(doc(db, 'emailCredentials', emailId));
            this.showToast('Email credentials deleted!', 'success');
            await this.loadEmails();
        } catch (error) {
            console.error('Error deleting email:', error);
            this.showToast('Error deleting email credentials', 'error');
        }
    }

    // ==================== UTILITIES ====================
    closeAllModals() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.classList.add('hidden');
        });
    }

    showToast(message, type = 'success') {
        if (!this.toast) return;

        const icon = this.toast.querySelector('.toast-icon');
        const msgEl = this.toast.querySelector('.toast-message');

        msgEl.textContent = message;
        this.toast.classList.remove('hidden', 'error');

        if (type === 'error') {
            this.toast.classList.add('error');
            if (icon) icon.setAttribute('data-feather', 'alert-circle');
        } else {
            if (icon) icon.setAttribute('data-feather', 'check-circle');
        }

        if (typeof feather !== 'undefined') feather.replace();

        setTimeout(() => {
            this.toast.classList.add('hidden');
        }, 3000);
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the application
const app = new AccessControlApp();

// Make app globally accessible for inline event handlers
window.app = app;
