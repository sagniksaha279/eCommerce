document.addEventListener('DOMContentLoaded', function() {
    const toggleSidebarBtn = document.getElementById('toggleSidebar');
    const sidebar = document.getElementById('sidebar');
    const accountBtn = document.getElementById('accountBtn');
    const mobileAccountBtn = document.getElementById('mobileAccountBtn');
    const accountPanel = document.getElementById('accountPanel');
    const mobileAccount = document.getElementById('mobileAccount');
    const overlay = document.getElementById('overlay');
    const navbarToggler = document.querySelector('.navbar-toggler');
    const mainNavbar = document.getElementById('mainNavbar');
    
    document.addEventListener('click', function(e) {
        if (mobileAccountBtn && mobileAccount && 
            !mobileAccountBtn.contains(e.target) && 
            !mobileAccount.contains(e.target)) {
            mobileAccount.classList.remove('show');
        }
    
        if (window.innerWidth < 992 && mainNavbar && 
            mainNavbar.classList.contains('show') &&
            !navbarToggler.contains(e.target) &&
            !mainNavbar.contains(e.target)) {
            const bsCollapse = new bootstrap.Collapse(mainNavbar);
            bsCollapse.hide();
        }
    });
    
    if (toggleSidebarBtn && sidebar) {
        toggleSidebarBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            sidebar.classList.toggle('hide');
            overlay.classList.toggle('show');
            
            if (accountPanel.classList.contains('show'))
                accountPanel.classList.remove('show');
         
            if (mobileAccount.classList.contains('show')) 
                mobileAccount.classList.remove('show');
            
            
            if (window.innerWidth < 992 && mainNavbar && mainNavbar.classList.contains('show')) {
                const bsCollapse = new bootstrap.Collapse(mainNavbar);
                bsCollapse.hide();
            }
        });
    }
    
    if (accountBtn && accountPanel) {
        accountBtn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            accountPanel.classList.toggle('show');
            overlay.classList.toggle('show');
            
            if (sidebar && !sidebar.classList.contains('hide'))
                sidebar.classList.add('hide');

            if (mobileAccount.classList.contains('show')) 
                mobileAccount.classList.remove('show');
            
            if (window.innerWidth < 992 && mainNavbar && mainNavbar.classList.contains('show')) {
                const bsCollapse = new bootstrap.Collapse(mainNavbar);
                bsCollapse.hide();
            }
        });
    }
    
    if (mobileAccountBtn && mobileAccount) {
        mobileAccountBtn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            mobileAccount.classList.toggle('show');
            if (accountPanel.classList.contains('show')) {
                accountPanel.classList.remove('show');
                overlay.classList.remove('show');
            }
            
            if (sidebar && !sidebar.classList.contains('hide')) {
                sidebar.classList.add('hide');
            }
        });
    }
    if (overlay) {
        overlay.addEventListener('click', function() {
            if (sidebar) {
                sidebar.classList.add('hide');
            }
            if (accountPanel) {
                accountPanel.classList.remove('show');
            }
            if (mobileAccount) {
                mobileAccount.classList.remove('show');
            }
            overlay.classList.remove('show');
    
            if (window.innerWidth < 992 && mainNavbar && mainNavbar.classList.contains('show')) {
                const bsCollapse = new bootstrap.Collapse(mainNavbar);
                bsCollapse.hide();
            }
        });
    }

    const accountLinks = document.querySelectorAll('.account-panel a, .mobile-account a');
    accountLinks.forEach(link => {
        link.addEventListener('click', function() {
            if (accountPanel) 
                accountPanel.classList.remove('show');
            
            if (mobileAccount) 
                mobileAccount.classList.remove('show');
        
            if (overlay)
                overlay.classList.remove('show');
        
            if (window.innerWidth < 992 && mainNavbar && mainNavbar.classList.contains('show')) {
                const bsCollapse = new bootstrap.Collapse(mainNavbar);
                bsCollapse.hide();
            }
        });
    });

    const cartLink = document.querySelector('.cart-link');
    if (cartLink) {
        cartLink.addEventListener('click', function() {
            // Close all panels
            if (sidebar) sidebar.classList.add('hide');
            if (accountPanel) accountPanel.classList.remove('show');
            if (mobileAccount) mobileAccount.classList.remove('show');
            if (overlay) overlay.classList.remove('show');
            
            // Close navbar on mobile
            if (window.innerWidth < 992 && mainNavbar && mainNavbar.classList.contains('show')) {
                const bsCollapse = new bootstrap.Collapse(mainNavbar);
                bsCollapse.hide();
            }
        });
    }
    
    // Handle window resize
    window.addEventListener('resize', function() {
        if (window.innerWidth < 992 && accountPanel) {
            accountPanel.classList.remove('show');
            overlay.classList.remove('show');
        }
        if (window.innerWidth >= 992 && mobileAccount)
            mobileAccount.classList.remove('show');

        if (overlay) {
            const sidebarHidden = sidebar ? sidebar.classList.contains('hide') : true;
            const accountPanelHidden = accountPanel ? !accountPanel.classList.contains('show') : true;
            
            if (sidebarHidden && accountPanelHidden) {
                overlay.classList.remove('show');
            }
        }
    });
    if (mainNavbar) {
        mainNavbar.addEventListener('show.bs.collapse', function () {
            if (mobileAccount) {
                mobileAccount.classList.remove('show');
            }
            
            // Close other panels
            if (accountPanel) accountPanel.classList.remove('show');
            if (sidebar) sidebar.classList.add('hide');
            if (overlay) overlay.classList.remove('show');
        });
        
        mainNavbar.addEventListener('hidden.bs.collapse', function () {
            if (overlay) overlay.classList.remove('show');
        });
    }
});
const searchToggle = document.getElementById('searchToggle');
const searchExpanded = document.getElementById('searchExpanded');
const mainNavbar = document.getElementById('mainNavbar');

if (searchToggle && searchExpanded) {
    searchToggle.addEventListener('click', function(e) {
        e.stopPropagation();
        searchToggle.classList.toggle('active');
        searchExpanded.classList.toggle('show');

        closeAllPanels();
        if (mainNavbar && mainNavbar.classList.contains('show')) {
            const bsCollapse = new bootstrap.Collapse(mainNavbar);
            bsCollapse.hide();
        }
    });
    
    document.addEventListener('click', function(e) {
        if (!searchToggle.contains(e.target) && !searchExpanded.contains(e.target)) {
            searchToggle.classList.remove('active');
            searchExpanded.classList.remove('show');
        }
    });
}

function closeAllPanels() {
    if (sidebar) sidebar.classList.add('hide');
    if (accountPanel) accountPanel.classList.remove('show');
    if (mobileAccount) mobileAccount.classList.remove('show');
    if (overlay) overlay.classList.remove('show');
}

document.addEventListener('DOMContentLoaded', function() {
    const navbarToggler = document.querySelector('.navbar-toggler');
    const mainNavbar = document.getElementById('mainNavbar');
    
    if (navbarToggler && mainNavbar) {
        navbarToggler.removeAttribute('data-bs-toggle');
        navbarToggler.removeAttribute('data-bs-target');
        
        navbarToggler.addEventListener('click', function() {
            const isExpanded = navbarToggler.getAttribute('aria-expanded') === 'true';
            
            if (isExpanded) {
                navbarToggler.setAttribute('aria-expanded', 'false');
                mainNavbar.classList.remove('show');
            } else {
                navbarToggler.setAttribute('aria-expanded', 'true');
                mainNavbar.classList.add('show');
                closeAllPanels();
            }
        });
    }
});
document.addEventListener('DOMContentLoaded', function () {
    const mainNavbar = document.getElementById('mainNavbar');
    const navbarToggler = document.querySelector('.navbar-toggler');

    if (window.innerWidth < 992 && mainNavbar && navbarToggler) {
        mainNavbar.classList.add('show');
        navbarToggler.setAttribute('aria-expanded', 'true');
    }
});

document.addEventListener("click", (e) => {
    if (!accountPanel.contains(e.target) && !accountBtn.contains(e.target)) {
        accountPanel.classList.remove("show");
    }
});

const searchDiv = document.getElementById('searchExpanded');
const categoryWrapper = searchDiv.querySelector('.search-category-wrapper');
const categorySelected = categoryWrapper.querySelector('.search-category-selected');
const categoryOptions = categoryWrapper.querySelector('.search-category-options');
const categoryItems = categoryOptions.querySelectorAll('li');

searchDiv.addEventListener('click', () => {
    categoryOptions.style.display = categoryOptions.style.display === 'block' ? 'none' : 'block';
});

categoryItems.forEach(item => {
    item.addEventListener('click', (e) => {
        e.stopPropagation(); 
        categorySelected.textContent = item.textContent;
        categoryOptions.style.display = 'none';
    });
});

document.addEventListener('click', (e) => {
    if (!searchDiv.contains(e.target)) {
        categoryOptions.style.display = 'none';
    }
});
