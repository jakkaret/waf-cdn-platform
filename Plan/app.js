/* ============================================
   WAF CDN Platform — Interactive JavaScript
   ============================================ */

document.addEventListener('DOMContentLoaded', () => {
  // ── Navbar Scroll Effect ──
  const navbar = document.getElementById('navbar');
  const navLinks = document.querySelectorAll('.nav-link');
  const sections = document.querySelectorAll('.section, .hero');

  window.addEventListener('scroll', () => {
    // Navbar background
    if (window.scrollY > 50) {
      navbar.classList.add('scrolled');
    } else {
      navbar.classList.remove('scrolled');
    }

    // Active nav link
    let currentSection = '';
    sections.forEach(section => {
      const sectionTop = section.offsetTop - 120;
      if (window.scrollY >= sectionTop) {
        currentSection = section.getAttribute('id');
      }
    });

    navLinks.forEach(link => {
      link.classList.remove('active');
      if (link.dataset.section === currentSection) {
        link.classList.add('active');
      }
    });

    // Animate flow steps on scroll
    animateFlowSteps();
  });

  // ── Smooth Scroll Nav ──
  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = document.querySelector(link.getAttribute('href'));
      if (target) {
        target.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });

  // ── Mobile Nav Toggle ──
  const navToggle = document.getElementById('nav-toggle');
  const navLinksContainer = document.querySelector('.nav-links');
  if (navToggle) {
    navToggle.addEventListener('click', () => {
      navLinksContainer.classList.toggle('mobile-open');
    });
  }

  // ── Architecture Diagram — Node Click ──
  const archNodes = document.querySelectorAll('.arch-node');
  const infoPanel = document.getElementById('info-panel');
  const infoTitle = document.getElementById('info-title');
  const infoBody = document.getElementById('info-body');
  const infoClose = document.getElementById('info-close');

  const nodeInfo = {
    user: {
      title: '👤 User / Client',
      content: `
        <ul>
          <li>ผู้ใช้ปลายทางเข้าเว็บผ่าน browser</li>
          <li>พิมพ์ domain เช่น example.com</li>
          <li>Browser จะ query DNS เพื่อหา IP address</li>
          <li>Request จะถูกส่งผ่าน HTTPS ไปยัง CDN ของเรา</li>
          <li>User ไม่เห็น IP ของ Origin จริง (ซ่อนไว้หลัง CDN+WAF)</li>
        </ul>
      `
    },
    dns: {
      title: '🌐 DNS — Domain Name System',
      content: `
        <ul>
          <li><strong>ทำอะไร:</strong> แปลงชื่อ domain → IP address ของ CDN</li>
          <li><strong>CNAME Record:</strong> example.com → proxy.waf-cdn.com</li>
          <li><strong>TXT Record:</strong> ใช้ verify ว่า domain นี้เป็นของ user จริง</li>
          <li><strong>DNS Provider:</strong> Cloudflare, Route53, หรือ registrar อื่นๆ</li>
          <li><strong>สำคัญ:</strong> User ต้อง set DNS ที่ registrar ก่อนระบบถึงจะทำงาน</li>
        </ul>
      `
    },
    cdn: {
      title: '⚡ CDN Edge — Content Delivery Network',
      content: `
        <ul>
          <li><strong>SSL Termination:</strong> HTTPS decrypt ที่นี่ (Let's Encrypt cert)</li>
          <li><strong>Cache Layer:</strong> เก็บ static files (images, CSS, JS) ไว้ที่ edge</li>
          <li><strong>Gzip/Brotli:</strong> บีบอัด response ให้เล็กลง</li>
          <li><strong>Multi-Region:</strong> Edge nodes ที่ SG, JP, TH</li>
          <li><strong>ถ้า cache HIT:</strong> ตอบกลับทันที ไม่ต้องไปถึง WAF/Origin</li>
          <li><strong>ถ้า cache MISS:</strong> ส่ง request ต่อไปที่ WAF</li>
        </ul>
      `
    },
    waf: {
      title: '🛡️ WAF — Web Application Firewall',
      content: `
        <ul>
          <li><strong>ModSecurity v3:</strong> Open-source WAF engine</li>
          <li><strong>OWASP CRS:</strong> Core Rule Set — กรอง SQL Injection, XSS, RCE</li>
          <li><strong>Custom Rules:</strong> เพิ่ม rule เฉพาะ per origin ได้</li>
          <li><strong>IP Blocking:</strong> Block IP ที่โจมตี</li>
          <li><strong>Rate Limiting:</strong> จำกัด request rate</li>
          <li><strong>ถ้า request อันตราย:</strong> Block → return 403</li>
          <li><strong>ถ้า request ปกติ:</strong> Pass → ส่งต่อไป Origin</li>
        </ul>
      `
    },
    origin: {
      title: '🖥️ Web Origin — เว็บไซต์ต้นทาง',
      content: `
        <ul>
          <li><strong>คืออะไร:</strong> Web server ของลูกค้า (เช่น Apache, Nginx, Node.js)</li>
          <li><strong>IP Address:</strong> ที่อยู่จริงของ server (ซ่อนจาก public)</li>
          <li><strong>Port:</strong> ปกติ 80 (HTTP) หรือ 443 (HTTPS)</li>
          <li><strong>Traffic ที่ถึงที่นี่:</strong> ผ่าน CDN + WAF แล้ว = clean traffic</li>
          <li><strong>Health Check:</strong> ระบบเช็คว่า origin ยัง online ทุก 1 นาที</li>
          <li><strong>1 Origin → 1 Admin:</strong> มีเจ้าของได้แค่คนเดียว</li>
        </ul>
      `
    }
  };

  archNodes.forEach(node => {
    node.addEventListener('click', () => {
      const infoKey = node.dataset.info;
      if (nodeInfo[infoKey]) {
        // Remove active from all nodes
        archNodes.forEach(n => n.classList.remove('active'));
        node.classList.add('active');

        // Update info panel
        infoTitle.textContent = nodeInfo[infoKey].title;
        infoBody.innerHTML = nodeInfo[infoKey].content;
        infoPanel.classList.add('visible');

        // Smooth scroll to panel
        setTimeout(() => {
          infoPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 300);
      }
    });
  });

  if (infoClose) {
    infoClose.addEventListener('click', () => {
      infoPanel.classList.remove('visible');
      archNodes.forEach(n => n.classList.remove('active'));
    });
  }

  // ── Module Tabs ──
  const moduleTabs = document.querySelectorAll('.module-tab');
  const modulePanels = document.querySelectorAll('.module-panel');

  moduleTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetModule = tab.dataset.module;

      // Update active tab
      moduleTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      // Show target panel
      modulePanels.forEach(panel => {
        panel.classList.remove('active');
        if (panel.id === `panel-${targetModule}`) {
          panel.classList.add('active');
        }
      });
    });
  });

  // ── Flow Steps Animation ──
  function animateFlowSteps() {
    const flowSteps = document.querySelectorAll('.flow-step');
    flowSteps.forEach(step => {
      const rect = step.getBoundingClientRect();
      const windowHeight = window.innerHeight;
      if (rect.top < windowHeight * 0.8) {
        step.classList.add('visible');
      }
    });
  }

  // Initial check
  animateFlowSteps();

  // ── Stat Counter Animation ──
  function animateCounters() {
    const counters = document.querySelectorAll('.stat-number, .summary-number');
    counters.forEach(counter => {
      const target = parseInt(counter.textContent);
      if (isNaN(target) || counter.dataset.animated) return;

      const rect = counter.getBoundingClientRect();
      if (rect.top > window.innerHeight) return;

      counter.dataset.animated = 'true';
      let current = 0;
      const increment = target / 30;
      const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
          current = target;
          clearInterval(timer);
        }
        counter.textContent = Math.round(current);
      }, 40);
    });
  }

  window.addEventListener('scroll', animateCounters);
  animateCounters();

  // ── Intersection Observer for fade-in ──
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }
    });
  }, observerOptions);

  // Observe concept cards and entity cards
  document.querySelectorAll('.concept-card, .entity, .summary-card').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'all 0.6s cubic-bezier(0.4, 0, 0.2, 1)';
    observer.observe(el);
  });

  // Add stagger delay to concept cards
  document.querySelectorAll('.concept-card').forEach((card, index) => {
    card.style.transitionDelay = `${index * 0.1}s`;
  });

  document.querySelectorAll('.entity').forEach((entity, index) => {
    entity.style.transitionDelay = `${index * 0.15}s`;
  });

  document.querySelectorAll('.summary-card').forEach((card, index) => {
    card.style.transitionDelay = `${index * 0.1}s`;
  });

  // ── Parallax for background glows ──
  window.addEventListener('scroll', () => {
    const scrollY = window.scrollY;
    document.querySelectorAll('.bg-glow').forEach((glow, index) => {
      const speed = (index + 1) * 0.03;
      glow.style.transform = `translateY(${scrollY * speed}px)`;
    });
  });

  console.log('🛡️ WAF CDN Platform — Architecture Plan loaded');
});
