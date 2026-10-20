/**
 * ShieldSense - Connected Dashboard Screen & AI Protection Controller
 * 
 * Manages:
 * - Immediate transition from "Connect Gmail" to the Connected Dashboard
 * - Left Sidebar navigation (Inbox, Threat Inbox, Live AI Scanner, Attachments, Links, Settings)
 * - Segmented Tab control ("All (6)", "Safe (6)", "Flagged (0)")
 * - Live Search filtering
 * - 5 Realistic Example Emails with `Safe (X)` badges, pill tags, and chevron expansion
 * - Multi-Signal Forensic Investigation Drawer
 */

document.addEventListener('DOMContentLoaded', () => {

  // ==========================================
  // 1. STATE & DATASETS
  // ==========================================
  let state = {
    currentView: 'landing', // 'landing', 'connect', or 'dashboard'
    currentPane: 'dash-pane-inbox',
    activeTabFilter: 'all', // 'all', 'safe', 'flagged'
    searchQuery: '',
    selectedEmailId: null,
    soundEnabled: true,
    userEmail: 'alex.security@gmail.com',
    emails: []
  };

  // 5 Realistic Example Emails + Threat Data
  const MOCK_GMAIL_INBOX = [
    {
      id: 'msg_docusign_01',
      senderName: 'DocuSign System',
      senderEmail: 'docusign@system-notify.net',
      sender: 'DocuSign System <docusign@system-notify.net>',
      date: '10:42 AM',
      subject: 'Completed: Consulting Services Agreement 2026',
      isSubjectHighlighted: false,
      preview: 'All parties have successfully signed Consulting_Agreement_2026.pdf. You can view or download the completed document and audit trail directly...',
      body: 'All parties have successfully signed Consulting_Agreement_2026.pdf. You can view or download the completed document and audit trail directly from your secure DocuSign vault. Document ID: 9482-ADK-8812.',
      links: [],
      attachments: [{ name: 'Consulting_Agreement_2026.pdf', size: 1468006, sizeFormatted: '1.4 MB' }],
      riskScore: 3,
      riskLevel: 'SAFE',
      riskBadgeText: 'Safe (3)',
      isFlagged: false,
      isQuarantined: false
    },
    {
      id: 'msg_stripe_02',
      senderName: 'Stripe Payments',
      senderEmail: 'notifications@stripe.com',
      sender: 'Stripe Payments <notifications@stripe.com>',
      date: '09:15 AM',
      subject: 'Payout of $4,850.00 is on the way to your bank account',
      isSubjectHighlighted: false,
      preview: 'Your daily payout of $4,850.00 has been initiated and should arrive in your bank account within 1-2 business days. View your transfer summary...',
      body: 'Your daily payout of $4,850.00 has been initiated and should arrive in your bank account within 1-2 business days. View your transfer breakdown, fee deductions, and invoice reconciliations on your Stripe dashboard.',
      links: [{ url: 'https://dashboard.stripe.com/payouts/po_8923481023', threatLevel: 'SAFE', score: 8 }],
      attachments: [],
      riskScore: 8,
      riskLevel: 'SAFE',
      riskBadgeText: 'Safe (8)',
      isFlagged: false,
      isQuarantined: false
    },
    {
      id: 'msg_github_03',
      senderName: 'GitHub Security',
      senderEmail: 'support@github.com',
      sender: 'GitHub Security <support@github.com>',
      date: 'Yesterday',
      subject: '[GitHub] A new public SSH key was added to your account',
      isSubjectHighlighted: false,
      preview: 'A new public key (id_ed25519_shield) was added to your account from IP address 192.88.99.12. If you did not perform this action...',
      body: 'A new public key (id_ed25519_shield) was added to your account from IP address 192.88.99.12. If you added this key, no further action is required. If you did not perform this action, visit your SSH settings to revoke access.',
      links: [{ url: 'https://github.com/settings/keys', threatLevel: 'SAFE', score: 6 }],
      attachments: [],
      riskScore: 6,
      riskLevel: 'SAFE',
      riskBadgeText: 'Safe (6)',
      isFlagged: false,
      isQuarantined: false
    },
    {
      id: 'msg_board_deck_04',
      senderName: 'Sarah Jenkins',
      senderEmail: 'sarah.jenkins@company.internal',
      sender: 'Sarah Jenkins <sarah.jenkins@company.internal>',
      date: 'Yesterday',
      subject: 'Q3 Board Meeting Presentation Deck & Financials',
      isSubjectHighlighted: true, // Distinct highlight color
      preview: 'Attached is the finalized slide deck for tomorrow\'s Q3 Board of Directors meeting. Please review section 4 financials before the call...',
      body: 'Attached is the finalized slide deck for tomorrow\'s Q3 Board of Directors meeting. Please review section 4 financials and customer retention projections before the executive briefing call tomorrow at 9:00 AM.',
      links: [{ url: 'https://company.internal/wiki/q3-strategy', threatLevel: 'SAFE', score: 4 }],
      attachments: [{ name: 'Q3_Board_Deck_Final.pptx', size: 15518924, sizeFormatted: '14.8 MB' }],
      riskScore: 4,
      riskLevel: 'SAFE',
      riskBadgeText: 'Safe (4)',
      isFlagged: false,
      isQuarantined: false
    },
    {
      id: 'msg_amazon_05',
      senderName: 'Amazon.com Orders',
      senderEmail: 'auto-confirm@amazon.com',
      sender: 'Amazon.com Orders <auto-confirm@amazon.com>',
      date: 'Aug 21',
      subject: 'Your order #114-892014-9921 of Cyber Sentinel hardware key has shipped',
      isSubjectHighlighted: false,
      preview: 'Great news! Your package is on its way. Track your package status or manage delivery preferences directly from your account...',
      body: 'Great news! Your package containing "Cyber Sentinel FIDO2 Security Key (2-pack)" is on its way. Estimated delivery date: Tomorrow by 8:00 PM. Carrier: Amazon Logistics. Tracking ID: TBA9284192039.',
      links: [{ url: 'https://www.amazon.com/progress-tracker/package/114-892014', threatLevel: 'SAFE', score: 12 }],
      attachments: [],
      riskScore: 12,
      riskLevel: 'SAFE',
      riskBadgeText: 'Safe (12)',
      isFlagged: false,
      isQuarantined: false
    }
  ];

  // Threat Inbox Sample (for Threat tab)
  const MOCK_THREAT_EMAILS = [
    {
      id: 'msg_threat_01',
      senderName: 'Account Security Alert',
      senderEmail: 'security@example-warning.com',
      sender: 'Account Security Alert <security@example-warning.com>',
      date: 'Aug 20',
      subject: 'Urgent: Immediate password reset required for your mailbox',
      isSubjectHighlighted: false,
      preview: 'URGENT! Your mailbox will be permanently suspended today unless you verify your credentials immediately...',
      body: 'URGENT! Your mailbox will be permanently suspended today unless you verify your credentials immediately at http://192.168.1.50/login/verify-account.',
      links: [{ url: 'http://192.168.1.50/login/verify-account', threatLevel: 'DANGEROUS', score: 96 }],
      attachments: [{ name: 'Security_Patch.exe', size: 430080, sizeFormatted: '420 KB' }],
      riskScore: 94,
      riskLevel: 'DANGEROUS',
      riskBadgeText: 'Dangerous (94)',
      isFlagged: true,
      isQuarantined: true
    }
  ];

  function initializeInbox() {
    state.emails = [...MOCK_GMAIL_INBOX];
  }

  initializeInbox();

  // ==========================================
  // 2. PROCEDURAL SOUND SYNTHESIZER
  // ==========================================
  let audioCtx = null;
  function getAudioContext() {
    if (!audioCtx) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (AudioContextClass) audioCtx = new AudioContextClass();
    }
    if (audioCtx && audioCtx.state === 'suspended') audioCtx.resume();
    return audioCtx;
  }

  function playSound(type) {
    if (!state.soundEnabled) return;
    try {
      const ctx = getAudioContext();
      if (!ctx) return;
      const now = ctx.currentTime;

      if (type === 'click') {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(800, now);
        osc.frequency.exponentialRampToValueAtTime(300, now + 0.04);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.04);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now);
        osc.stop(now + 0.04);
      } else if (type === 'safe-chime') {
        [523.25, 659.25, 783.99].forEach((freq, idx) => {
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          osc.type = 'sine';
          osc.frequency.setValueAtTime(freq, now + idx * 0.06);
          gain.gain.setValueAtTime(0.08, now + idx * 0.06);
          gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.06 + 0.25);
          osc.connect(gain);
          gain.connect(ctx.destination);
          osc.start(now + idx * 0.06);
          osc.stop(now + idx * 0.06 + 0.25);
        });
      }
    } catch (e) {}
  }

  // ==========================================
  // 3. TOAST ALERT SYSTEM
  // ==========================================
  const toastContainer = document.getElementById('toast-container');

  function showToast(message, type = 'info') {
    if (!toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast-msg ${type}`;
    let icon = 'ℹ️';
    if (type === 'safe') icon = '✅';
    else if (type === 'warning') icon = '⚠️';
    else if (type === 'error') icon = '🚨';

    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    toastContainer.appendChild(toast);
    playSound('click');

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(40px)';
      toast.style.transition = '0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  // ==========================================
  // 4. ROUTING & VIEW CONTROLLER
  // ==========================================
  const viewLanding = document.getElementById('view-landing');
  const viewConnect = document.getElementById('view-connect');
  const viewDashboard = document.getElementById('view-dashboard');
  const btnBackToLanding = document.getElementById('btn-back-to-landing');
  const topNavLogo = document.getElementById('top-nav-logo');
  const dashLogoBtn = document.getElementById('dash-logo-btn');
  const sidebarNavItems = document.querySelectorAll('.sidebar-nav-item');
  const dashPanes = document.querySelectorAll('.dash-pane');
  const dashTitle = document.getElementById('dash-current-title');
  const dashSubtitle = document.getElementById('dash-current-subtitle');

  function updateTopNavActiveState(routeKey) {
    const topNavLinks = document.querySelectorAll('.site-header .nav-link');
    topNavLinks.forEach(link => link.classList.remove('active'));

    if (routeKey === 'dashboard') {
      const el = document.getElementById('nav-link-dashboard');
      if (el) el.classList.add('active');
    } else if (routeKey === 'how-it-works') {
      const el = document.getElementById('nav-link-how-it-works');
      if (el) el.classList.add('active');
    } else if (routeKey === 'threat-inbox') {
      const el = document.getElementById('nav-link-threat-inbox');
      if (el) el.classList.add('active');
    } else if (routeKey === 'risk-analysis') {
      const el = document.getElementById('nav-link-risk-analysis');
      if (el) el.classList.add('active');
    } else if (routeKey === 'pricing') {
      const el = document.getElementById('nav-link-pricing');
      if (el) el.classList.add('active');
    }
  }

  function switchView(viewName) {
    state.currentView = viewName;
    if (viewName === 'dashboard') {
      if (viewLanding) viewLanding.classList.remove('active');
      if (viewConnect) viewConnect.classList.remove('active');
      if (viewDashboard) viewDashboard.classList.add('active');
      renderConnectedDashboard();
    } else if (viewName === 'connect') {
      if (viewLanding) viewLanding.classList.remove('active');
      if (viewDashboard) viewDashboard.classList.remove('active');
      if (viewConnect) viewConnect.classList.add('active');
    } else {
      if (viewDashboard) viewDashboard.classList.remove('active');
      if (viewConnect) viewConnect.classList.remove('active');
      if (viewLanding) viewLanding.classList.add('active');
    }
  }

  function switchDashboardPane(paneId) {
    if (!paneId) paneId = 'dash-pane-inbox';
    state.currentPane = paneId;

    dashPanes.forEach(pane => {
      pane.classList.toggle('active', pane.id === paneId);
    });

    sidebarNavItems.forEach(item => {
      item.classList.toggle('active', item.dataset.pane === paneId);
    });

    if (paneId === 'dash-pane-inbox') {
      if (dashTitle) dashTitle.textContent = 'Gmail Inbox';
      if (dashSubtitle) dashSubtitle.textContent = 'ShieldSense scans every inbound email, attachment, and embedded link automatically.';
    } else if (paneId === 'dash-pane-threats') {
      if (dashTitle) dashTitle.textContent = 'Threat Inbox';
      if (dashSubtitle) dashSubtitle.textContent = 'High & Moderate risk threats flagged by the AI multi-signal engine.';
    } else if (paneId === 'dash-pane-scanner') {
      if (dashTitle) dashTitle.textContent = 'Live AI Scanner';
      if (dashSubtitle) dashSubtitle.textContent = 'Active multi-signal heuristic engine inspecting inbound Gmail payloads in real-time.';
    } else if (paneId === 'dash-pane-attachments') {
      if (dashTitle) dashTitle.textContent = 'Discovered Attachments';
      if (dashSubtitle) dashSubtitle.textContent = 'Files extracted from Gmail messages with security risk ratings.';
    } else if (paneId === 'dash-pane-links') {
      if (dashTitle) dashTitle.textContent = 'Discovered Links';
      if (dashSubtitle) dashSubtitle.textContent = 'URLs extracted from Gmail messages with threat scores.';
    } else if (paneId === 'dash-pane-settings') {
      if (dashTitle) dashTitle.textContent = 'Security Settings';
      if (dashSubtitle) dashSubtitle.textContent = 'Configure stream thresholds, notifications, and Google OAuth 2.0 integration.';
    }

    renderConnectedDashboard();
  }

  function navigateTo(targetHash, options = {}) {
    const overlay = document.getElementById('investigation-overlay');
    if (overlay && overlay.classList.contains('active') && !options.keepDrawer) {
      closeInvestigationDrawer();
    }

    let hash = targetHash || window.location.hash || '#overview';
    if (!hash.startsWith('#')) hash = '#' + hash;
    const lower = hash.toLowerCase();

    if (lower === '#connect' || lower === '#connect-gmail' || lower === '#connect-email') {
      switchView('connect');
      updateTopNavActiveState('');
      if (window.location.hash !== '#connect') history.replaceState(null, '', '#connect');
      window.scrollTo({ top: 0, behavior: 'smooth' });
      const emailInput = document.getElementById('input-connect-email');
      const errBox = document.getElementById('connect-email-error');
      if (errBox) errBox.textContent = '';
      if (emailInput) {
        emailInput.classList.remove('input-error');
        setTimeout(() => emailInput.focus(), 80);
      }
    } else if (lower === '#dashboard' || lower === '#dashboard/inbox' || lower === '#inbox') {
      switchView('dashboard');
      switchDashboardPane('dash-pane-inbox');
      updateTopNavActiveState('dashboard');
      if (window.location.hash !== '#dashboard') history.replaceState(null, '', '#dashboard');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else if (lower === '#threat-inbox' || lower === '#dashboard/threats' || lower === '#threats') {
      switchView('dashboard');
      switchDashboardPane('dash-pane-threats');
      updateTopNavActiveState('threat-inbox');
      if (window.location.hash !== '#threat-inbox') history.replaceState(null, '', '#threat-inbox');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else if (lower === '#dashboard/links' || lower === '#links') {
      switchView('dashboard');
      switchDashboardPane('dash-pane-links');
      updateTopNavActiveState('dashboard');
      if (window.location.hash !== '#dashboard/links') history.replaceState(null, '', '#dashboard/links');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else if (lower === '#dashboard/attachments' || lower === '#attachments') {
      switchView('dashboard');
      switchDashboardPane('dash-pane-attachments');
      updateTopNavActiveState('dashboard');
      if (window.location.hash !== '#dashboard/attachments') history.replaceState(null, '', '#dashboard/attachments');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else if (lower === '#dashboard/live-scanner' || lower === '#scanner') {
      switchView('dashboard');
      switchDashboardPane('dash-pane-scanner');
      updateTopNavActiveState('dashboard');
      if (window.location.hash !== '#dashboard/live-scanner') history.replaceState(null, '', '#dashboard/live-scanner');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else if (lower === '#dashboard/settings' || lower === '#settings') {
      switchView('dashboard');
      switchDashboardPane('dash-pane-settings');
      updateTopNavActiveState('dashboard');
      if (window.location.hash !== '#dashboard/settings') history.replaceState(null, '', '#dashboard/settings');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else if (lower === '#how-it-works' || lower === '#features') {
      switchView('landing');
      updateTopNavActiveState('how-it-works');
      if (window.location.hash !== '#how-it-works') history.replaceState(null, '', '#how-it-works');
      setTimeout(() => {
        const el = document.getElementById('how-it-works');
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 50);
    } else if (lower === '#risk-analysis') {
      switchView('landing');
      updateTopNavActiveState('risk-analysis');
      if (window.location.hash !== '#risk-analysis') history.replaceState(null, '', '#risk-analysis');
      setTimeout(() => {
        const el = document.getElementById('risk-analysis');
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 50);
    } else if (lower === '#pricing') {
      switchView('landing');
      updateTopNavActiveState('pricing');
      if (window.location.hash !== '#pricing') history.replaceState(null, '', '#pricing');
      setTimeout(() => {
        const el = document.getElementById('pricing');
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 50);
    } else {
      switchView('landing');
      updateTopNavActiveState('');
      if (window.location.hash !== '#overview') history.replaceState(null, '', '#overview');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }

  // Top Nav Link Click Listeners
  document.querySelectorAll('.site-header .nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = link.getAttribute('href');
      playSound('click');
      navigateTo(target);
    });
  });

  // Top Nav Logo: Always returns to Dashboard
  if (topNavLogo) {
    topNavLogo.addEventListener('click', (e) => {
      e.preventDefault();
      playSound('click');
      navigateTo('#dashboard');
    });
  }

  // Sidebar Logo: Returns to Dashboard
  if (dashLogoBtn) {
    dashLogoBtn.addEventListener('click', (e) => {
      e.preventDefault();
      playSound('click');
      navigateTo('#dashboard');
    });
  }

  // Sidebar Navigation Click Listeners
  sidebarNavItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      playSound('click');
      const href = item.getAttribute('href');
      if (href === '#pricing') {
        navigateTo('#pricing');
      } else if (item.dataset.pane) {
        switchDashboardPane(item.dataset.pane);
        if (item.dataset.pane === 'dash-pane-threats') {
          updateTopNavActiveState('threat-inbox');
          history.replaceState(null, '', '#threat-inbox');
        } else if (item.dataset.pane === 'dash-pane-inbox') {
          updateTopNavActiveState('dashboard');
          history.replaceState(null, '', '#dashboard');
        } else if (item.dataset.pane === 'dash-pane-links') {
          history.replaceState(null, '', '#dashboard/links');
        } else if (item.dataset.pane === 'dash-pane-attachments') {
          history.replaceState(null, '', '#dashboard/attachments');
        } else if (item.dataset.pane === 'dash-pane-scanner') {
          history.replaceState(null, '', '#dashboard/live-scanner');
        } else if (item.dataset.pane === 'dash-pane-settings') {
          history.replaceState(null, '', '#dashboard/settings');
        }
      } else if (href) {
        navigateTo(href);
      }
    });
  });

  if (btnBackToLanding) {
    btnBackToLanding.addEventListener('click', (e) => {
      e.preventDefault();
      playSound('click');
      navigateTo('#overview');
    });
  }

  // Connect Gmail buttons navigate to the Email Entry Step Screen
  document.querySelectorAll('.btn-trigger-connect-gmail').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      playSound('click');
      navigateTo('#connect');
    });
  });

  // Email Entry Step Form & Validation
  const formConnectEmail = document.getElementById('form-connect-email');
  const inputConnectEmail = document.getElementById('input-connect-email');
  const connectEmailError = document.getElementById('connect-email-error');
  const btnFillDemoEmail = document.getElementById('btn-fill-demo-email');

  function validateEmailFormat(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
  }

  if (formConnectEmail) {
    formConnectEmail.addEventListener('submit', (e) => {
      e.preventDefault();
      const emailVal = inputConnectEmail ? inputConnectEmail.value.trim() : '';

      if (!emailVal) {
        if (connectEmailError) connectEmailError.textContent = 'Please enter your Gmail address.';
        if (inputConnectEmail) {
          inputConnectEmail.classList.add('input-error');
          inputConnectEmail.focus();
        }
        playSound('click');
        return;
      }

      if (!validateEmailFormat(emailVal)) {
        if (connectEmailError) connectEmailError.textContent = 'Please enter a valid email address (e.g. name@gmail.com).';
        if (inputConnectEmail) {
          inputConnectEmail.classList.add('input-error');
          inputConnectEmail.focus();
        }
        playSound('click');
        return;
      }

      // Valid email: proceed to dashboard
      state.userEmail = emailVal;
      if (connectEmailError) connectEmailError.textContent = '';
      if (inputConnectEmail) inputConnectEmail.classList.remove('input-error');

      playSound('safe-chime');
      navigateTo('#dashboard');
      showToast(`Connected ${emailVal}! Live AI Protection Active.`, 'safe');
    });
  }

  if (inputConnectEmail) {
    inputConnectEmail.addEventListener('input', () => {
      if (connectEmailError && connectEmailError.textContent) {
        connectEmailError.textContent = '';
        inputConnectEmail.classList.remove('input-error');
      }
    });
  }

  if (btnFillDemoEmail) {
    btnFillDemoEmail.addEventListener('click', () => {
      if (inputConnectEmail) {
        inputConnectEmail.value = 'alex.security@gmail.com';
        inputConnectEmail.classList.remove('input-error');
        if (connectEmailError) connectEmailError.textContent = '';
        inputConnectEmail.focus();
        playSound('click');
      }
    });
  }

  // Hero secondary link "See How It Works"
  document.querySelectorAll('a[href="#how-it-works"]').forEach(el => {
    el.addEventListener('click', (e) => {
      e.preventDefault();
      playSound('click');
      navigateTo('#how-it-works');
    });
  });

  // Free Trial & Paid Pricing Plan Buttons
  const btnStartFreeTrial = document.getElementById('btn-start-free-trial');
  if (btnStartFreeTrial) {
    btnStartFreeTrial.addEventListener('click', (e) => {
      e.preventDefault();
      playSound('safe-chime');
      navigateTo('#dashboard');
      showToast('Free Trial Activated! Welcome to ShieldSense.', 'safe');
    });
  }

  document.querySelectorAll('.btn-choose-paid-plan').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const plan = btn.dataset.plan || 'ShieldSense Pro';
      playSound('safe-chime');
      navigateTo('#dashboard');
      showToast(`Selected ${plan}! Live protection enabled.`, 'safe');
    });
  });

  // Settings Buttons
  const btnSaveSettings = document.getElementById('btn-save-oauth-settings');
  if (btnSaveSettings) {
    btnSaveSettings.addEventListener('click', (e) => {
      e.preventDefault();
      showToast('Settings saved successfully.', 'safe');
    });
  }

  const btnResetDemo = document.getElementById('btn-reset-demo-stream');
  if (btnResetDemo) {
    btnResetDemo.addEventListener('click', (e) => {
      e.preventDefault();
      initializeInbox();
      renderConnectedDashboard();
      showToast('Mock Inbox Stream Reloaded.', 'info');
    });
  }

  window.addEventListener('hashchange', () => {
    navigateTo(window.location.hash);
  });

  // ==========================================
  // 5. DASHBOARD RENDERING & FILTERING
  // ==========================================
  const emailsContainer = document.getElementById('dash-emails-container');
  const threatsContainer = document.getElementById('dash-threats-container');
  const attachmentsTbody = document.getElementById('dash-attachments-tbody');
  const linksTbody = document.getElementById('dash-links-tbody');
  const searchInput = document.getElementById('dash-search-input');
  const segmentedTabBtns = document.querySelectorAll('.segmented-tab-btn');

  function renderInboxEmails() {
    if (!emailsContainer) return;
    const query = state.searchQuery.toLowerCase();
    const tab = state.activeTabFilter;

    let listToRender = [];
    if (tab === 'all') {
      listToRender = state.emails;
    } else if (tab === 'safe') {
      listToRender = state.emails.filter(e => e.riskLevel === 'SAFE');
    } else if (tab === 'flagged') {
      listToRender = state.emails.filter(e => e.isFlagged);
    }

    // Apply Search Filter
    const filtered = listToRender.filter(email => {
      if (!query) return true;
      return (
        email.senderName.toLowerCase().includes(query) ||
        email.senderEmail.toLowerCase().includes(query) ||
        email.subject.toLowerCase().includes(query) ||
        email.preview.toLowerCase().includes(query)
      );
    });

    if (filtered.length === 0) {
      emailsContainer.innerHTML = `
        <div style="text-align:center; padding:45px 20px; color:var(--text-dim);">
          <div style="font-size:1.8rem; margin-bottom:8px;">🛡️</div>
          <h4 style="color:var(--text-bright); font-size:1rem;">No emails match this filter</h4>
          <p style="font-size:0.82rem;">Try clearing search keywords or selecting "All (${state.emails.length})".</p>
        </div>
      `;
      return;
    }

    emailsContainer.innerHTML = filtered.map(email => {
      const hasAttachment = email.attachments && email.attachments.length > 0;
      const hasLink = email.links && email.links.length > 0;
      const highlightClass = email.isSubjectHighlighted ? 'highlight-subject' : '';

      return `
        <div class="email-row-card" data-id="${email.id}">
          <!-- Left portion: sender, subject, preview, tags -->
          <div class="email-row-main">
            <div class="email-sender-line">
              <span class="sender-name-bold">${email.senderName}</span>
              <span class="sender-email-muted">&lt;${email.senderEmail}&gt;</span>
              <span class="email-date-muted">${email.date}</span>
            </div>

            <div class="email-subject-line ${highlightClass}">
              ${email.subject}
            </div>

            <div class="email-preview-snippet">
              ${email.preview}
            </div>

            <div class="email-pill-tags-row">
              ${hasAttachment ? `<span class="tag-pill-dark">📎 ${email.attachments.length} attachment</span>` : ''}
              ${hasLink ? `<span class="tag-pill-dark">🔗 ${email.links.length} link</span>` : ''}
            </div>
          </div>

          <!-- Right portion: risk score badge & chevron arrow -->
          <div class="email-row-right">
            <div class="risk-pill-badge safe">
              ${email.riskBadgeText}
            </div>
            <div class="chevron-arrow-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="9 18 15 12 9 6"></polyline>
              </svg>
            </div>
          </div>
        </div>
      `;
    }).join('');

    // Attach click listener to open forensic drawer
    emailsContainer.querySelectorAll('.email-row-card').forEach(card => {
      card.addEventListener('click', () => {
        openInvestigationDrawer(card.dataset.id);
      });
    });
  }

  function renderThreatInbox() {
    if (!threatsContainer) return;
    const threats = MOCK_THREAT_EMAILS;

    threatsContainer.innerHTML = threats.map(email => {
      return `
        <div class="email-row-card" data-id="${email.id}" style="border-left: 3px solid var(--color-dangerous);">
          <div class="email-row-main">
            <div class="email-sender-line">
              <span class="sender-name-bold" style="color:var(--color-dangerous);">${email.senderName}</span>
              <span class="sender-email-muted">&lt;${email.senderEmail}&gt;</span>
              <span class="email-date-muted">${email.date}</span>
            </div>

            <div class="email-subject-line">
              ${email.subject}
            </div>

            <div class="email-preview-snippet" style="color:var(--cyber-cyan);">
              ${email.preview}
            </div>

            <div class="email-pill-tags-row">
              <span class="tag-pill-dark">📎 1 attachment</span>
              <span class="tag-pill-dark">🔗 1 link</span>
            </div>
          </div>

          <div class="email-row-right">
            <div class="risk-pill-badge dangerous">
              Dangerous (94)
            </div>
            <div class="chevron-arrow-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="9 18 15 12 9 6"></polyline>
              </svg>
            </div>
          </div>
        </div>
      `;
    }).join('');

    threatsContainer.querySelectorAll('.email-row-card').forEach(card => {
      card.addEventListener('click', () => {
        openInvestigationDrawer(card.dataset.id);
      });
    });
  }

  function renderAttachmentsView() {
    if (!attachmentsTbody) return;
    const allAttachments = [];
    state.emails.forEach(e => {
      if (e.attachments) {
        e.attachments.forEach(a => {
          allAttachments.push({ ...a, parentSubject: e.subject, parentSender: e.senderName, parentId: e.id, riskScore: e.riskScore });
        });
      }
    });

    attachmentsTbody.innerHTML = allAttachments.map(att => {
      return `
        <tr>
          <td><strong>📎 ${att.name}</strong></td>
          <td style="font-family:var(--font-mono); font-size:0.8rem;">${att.sizeFormatted}</td>
          <td style="color:var(--text-bright);">${att.parentSubject}</td>
          <td style="color:var(--text-dim); font-size:0.82rem;">${att.parentSender}</td>
          <td>
            <span class="risk-pill-badge safe">Safe (${att.riskScore})</span>
          </td>
          <td>
            <button class="btn-secondary-link btn-inspect-parent" data-parent-id="${att.parentId}" style="padding:4px 10px; font-size:0.75rem;">
              Inspect Email
            </button>
          </td>
        </tr>
      `;
    }).join('');

    attachmentsTbody.querySelectorAll('.btn-inspect-parent').forEach(btn => {
      btn.addEventListener('click', () => openInvestigationDrawer(btn.dataset.parentId));
    });
  }

  function renderLinksView() {
    if (!linksTbody) return;
    const allLinks = [];
    state.emails.forEach(e => {
      if (e.links) {
        e.links.forEach(l => {
          allLinks.push({ ...l, parentSubject: e.subject, parentSender: e.senderName, parentId: e.id });
        });
      }
    });

    linksTbody.innerHTML = allLinks.map(link => {
      return `
        <tr>
          <td style="max-width:280px; word-break:break-all;"><strong>🔗 ${link.url}</strong></td>
          <td style="color:var(--text-bright);">${link.parentSubject}</td>
          <td style="color:var(--text-dim); font-size:0.82rem;">${link.parentSender}</td>
          <td>
            <span class="risk-pill-badge safe">Safe (${link.score})</span>
          </td>
          <td>
            <button class="btn-secondary-link btn-inspect-parent" data-parent-id="${link.parentId}" style="padding:4px 10px; font-size:0.75rem;">
              Inspect Email
            </button>
          </td>
        </tr>
      `;
    }).join('');

    linksTbody.querySelectorAll('.btn-inspect-parent').forEach(btn => {
      btn.addEventListener('click', () => openInvestigationDrawer(btn.dataset.parentId));
    });
  }

  function updateCounts() {
    const totalSafe = state.emails.filter(e => e.riskLevel === 'SAFE').length;
    const totalFlagged = state.emails.filter(e => e.isFlagged).length;

    const tAll = document.getElementById('tab-count-all');
    const tSafe = document.getElementById('tab-count-safe');
    const tFlagged = document.getElementById('tab-count-flagged');

    if (tAll) tAll.textContent = state.emails.length;
    if (tSafe) tSafe.textContent = totalSafe;
    if (tFlagged) tFlagged.textContent = totalFlagged;

    const sInbox = document.getElementById('sidebar-count-inbox');
    if (sInbox) sInbox.textContent = state.emails.length;
  }

  function updateAccountEmailUI() {
    const emailPill = document.getElementById('dash-account-email-pill');
    if (emailPill && state.userEmail) {
      emailPill.textContent = `Protected: ${state.userEmail}`;
    }
  }

  function renderConnectedDashboard() {
    updateCounts();
    updateAccountEmailUI();
    renderInboxEmails();
    renderThreatInbox();
    renderAttachmentsView();
    renderLinksView();
  }

  // Segmented Tab Button Handler
  segmentedTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      segmentedTabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.activeTabFilter = btn.dataset.tabFilter;
      playSound('click');
      renderInboxEmails();
    });
  });

  // Search Input Handler
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value.trim();
      renderInboxEmails();
    });
  }

  // ==========================================
  // 6. FORENSIC INVESTIGATION DRAWER
  // ==========================================
  const drawerOverlay = document.getElementById('investigation-overlay');
  const btnCloseDrawer = document.getElementById('btn-close-investigation');
  const drawerScoreCard = document.getElementById('drawer-score-card');
  const drawerScoreNum = document.getElementById('drawer-score-num');
  const drawerThreatLabel = document.getElementById('drawer-threat-label');
  const drawerClassBadge = document.getElementById('drawer-classification-badge');
  const drawerSubject = document.getElementById('drawer-email-subject');
  const drawerSender = document.getElementById('drawer-email-sender');
  const drawerDate = document.getElementById('drawer-email-date');
  const drawerBodySnippet = document.getElementById('drawer-email-body-snippet');
  const drawerIntentList = document.getElementById('drawer-intent-findings-list');
  const drawerLinksList = document.getElementById('drawer-links-findings-list');
  const drawerAttachList = document.getElementById('drawer-attachments-findings-list');
  const drawerRecTitle = document.getElementById('drawer-recommendation-title');
  const drawerRecBody = document.getElementById('drawer-recommendation-body');
  const drawerBtnQuarantine = document.getElementById('drawer-btn-quarantine');
  const drawerBtnKeep = document.getElementById('drawer-btn-keep');

  function openInvestigationDrawer(emailId) {
    let email = state.emails.find(e => e.id === emailId);
    if (!email) {
      email = MOCK_THREAT_EMAILS.find(e => e.id === emailId);
    }
    if (!email) return;

    state.selectedEmailId = emailId;

    if (drawerSubject) drawerSubject.textContent = `Subject: "${email.subject}"`;
    if (drawerSender) drawerSender.textContent = `From: ${email.sender}`;
    if (drawerDate) drawerDate.textContent = `Received ${email.date} • ShieldSense Multi-Signal Audit`;
    if (drawerBodySnippet) drawerBodySnippet.textContent = `"${email.body}"`;

    if (drawerScoreNum) drawerScoreNum.textContent = email.riskBadgeText;
    if (drawerThreatLabel) {
      drawerThreatLabel.textContent = email.riskLevel === 'SAFE' ? 'LOW RISK • VERIFIED SAFE' : 'CRITICAL RISK DETECTED';
    }

    if (drawerClassBadge) {
      drawerClassBadge.className = `risk-pill-badge ${email.riskLevel.toLowerCase()}`;
      drawerClassBadge.textContent = email.riskLevel === 'SAFE' ? '🟢 Safe' : '🔴 Dangerous';
    }

    if (drawerScoreCard) {
      drawerScoreCard.className = `investigation-score-card ${email.riskLevel.toLowerCase()}`;
    }

    // Email Analysis Findings
    if (drawerIntentList) {
      drawerIntentList.innerHTML = `
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px; margin-bottom:10px;">
          <div style="font-size:0.78rem; color:var(--text-main); display:flex; align-items:center; gap:5px;">
            <span style="color:var(--cyber-cyan); font-weight:800;">✓</span><span>Sender domain verified</span>
          </div>
          <div style="font-size:0.78rem; color:var(--text-main); display:flex; align-items:center; gap:5px;">
            <span style="color:var(--cyber-cyan); font-weight:800;">✓</span><span>Message intent analyzed</span>
          </div>
          <div style="font-size:0.78rem; color:var(--text-main); display:flex; align-items:center; gap:5px;">
            <span style="color:var(--cyber-cyan); font-weight:800;">✓</span><span>Link security checked</span>
          </div>
          <div style="font-size:0.78rem; color:var(--text-main); display:flex; align-items:center; gap:5px;">
            <span style="color:var(--cyber-cyan); font-weight:800;">✓</span><span>Attachment signature safe</span>
          </div>
        </div>
        <div class="evidence-item-card safe">
          <div class="evidence-content">
            <h5>✓ Clean Sender & Message Payload</h5>
            <p>No credential phishing markers, spoofed headers, or malicious code detected.</p>
          </div>
          <span style="font-size:0.75rem; color:var(--color-safe); font-weight:700;">PASSED</span>
        </div>
      `;
    }

    // Links List
    if (drawerLinksList) {
      if (!email.links || email.links.length === 0) {
        drawerLinksList.innerHTML = `
          <div class="evidence-item-card safe">
            <div class="evidence-content">
              <h5>No External Hyperlinks</h5>
              <p>Message contains zero external hyperlinks.</p>
            </div>
          </div>
        `;
      } else {
        drawerLinksList.innerHTML = email.links.map(link => `
          <div class="evidence-item-card safe">
            <div class="evidence-content">
              <h5>🔗 ${link.url}</h5>
              <p>Standard HTTPS endpoint. Passed reputation inspection.</p>
            </div>
            <span class="risk-pill-badge safe">Safe (${link.score})</span>
          </div>
        `).join('');
      }
    }

    // Attachments List
    if (drawerAttachList) {
      if (!email.attachments || email.attachments.length === 0) {
        drawerAttachList.innerHTML = `
          <div class="evidence-item-card safe">
            <div class="evidence-content">
              <h5>No File Attachments</h5>
              <p>Message contains no binary or document attachments.</p>
            </div>
          </div>
        `;
      } else {
        drawerAttachList.innerHTML = email.attachments.map(att => `
          <div class="evidence-item-card safe">
            <div class="evidence-content">
              <h5>📎 ${att.name} (${att.sizeFormatted})</h5>
              <p>Standard document structure without executable payloads or macro triggers.</p>
            </div>
            <span class="risk-pill-badge safe">Safe (${email.riskScore})</span>
          </div>
        `).join('');
      }
    }

    if (drawerRecTitle) {
      drawerRecTitle.textContent = email.isQuarantined ? 'QUARANTINED' : 'KEEP IN INBOX';
    }
    if (drawerRecBody) {
      drawerRecBody.textContent = email.isQuarantined 
        ? 'This message is isolated in ShieldSense Quarantine.' 
        : 'This message is verified safe. All links and attachments have passed security audit.';
    }

    if (drawerBtnQuarantine) {
      drawerBtnQuarantine.textContent = email.isQuarantined ? '🔄 Release from Quarantine' : '🛡 Move to Quarantine';
    }

    if (drawerOverlay) drawerOverlay.classList.add('active');
    playSound('click');
  }

  function closeInvestigationDrawer() {
    if (drawerOverlay) drawerOverlay.classList.remove('active');
    state.selectedEmailId = null;
    playSound('click');
  }

  if (btnCloseDrawer) btnCloseDrawer.addEventListener('click', closeInvestigationDrawer);

  if (drawerOverlay) {
    drawerOverlay.addEventListener('click', (e) => {
      if (e.target === drawerOverlay) closeInvestigationDrawer();
    });
  }

  if (drawerBtnQuarantine) {
    drawerBtnQuarantine.addEventListener('click', () => {
      if (!state.selectedEmailId) return;
      const email = state.emails.find(e => e.id === state.selectedEmailId);
      if (!email) return;

      email.isQuarantined = !email.isQuarantined;
      email.isFlagged = email.isQuarantined;
      showToast(email.isQuarantined ? 'Moved email to Quarantine.' : 'Restored email to Inbox.', 'safe');
      renderConnectedDashboard();
      closeInvestigationDrawer();
    });
  }

  if (drawerBtnKeep) {
    drawerBtnKeep.addEventListener('click', () => {
      showToast('Email kept in inbox.', 'info');
      closeInvestigationDrawer();
    });
  }

  // Audio Toggle
  const soundToggleBtn = document.getElementById('sound-toggle-btn') || document.getElementById('landing-sound-toggle-btn');
  const soundOnSvgs = document.querySelectorAll('.sound-on-svg');
  const soundOffSvgs = document.querySelectorAll('.sound-off-svg');

  function updateSoundUI() {
    soundOnSvgs.forEach(el => el.style.display = state.soundEnabled ? 'block' : 'none');
    soundOffSvgs.forEach(el => el.style.display = state.soundEnabled ? 'none' : 'block');
  }

  if (soundToggleBtn) {
    soundToggleBtn.addEventListener('click', () => {
      state.soundEnabled = !state.soundEnabled;
      updateSoundUI();
      showToast(state.soundEnabled ? 'Audio FX Enabled' : 'Audio Muted', 'info');
    });
  }

  // Initialize
  const initialHash = window.location.hash || '#overview';
  navigateTo(initialHash);
  renderConnectedDashboard();

});
