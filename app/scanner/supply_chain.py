"""
WebGuard Supply-Chain Analysis & CVE Cross-Reference Engine
============================================================
Fingerprints third-party JS/CSS libraries loaded on a target page,
identifies their versions via CDN URL patterns and content-based regex,
and cross-references them against the OSV.dev vulnerability database.
"""

import re
import hashlib
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("WebGuardSupplyChain")

# ---------------------------------------------------------------------------
# Library Signature Database
# ---------------------------------------------------------------------------
# Each entry maps a library name to:
#   - "cdn_patterns": list of regex patterns matched against script/link URLs
#   - "content_patterns": list of regex patterns matched against fetched source code
#   - "ecosystem": the OSV ecosystem name for CVE lookups (usually "npm")
#   - "package": the exact package name in the ecosystem registry
#
# Version is always captured via a named group (?P<version>...)

LIBRARY_SIGNATURES = [
    {
        "name": "jQuery",
        "package": "jquery",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"jquery[/@-](?P<version>\d+\.\d+\.\d+)",
            r"jquery\.min\.js",
            r"jquery\.js",
        ],
        "content_patterns": [
            r"jQuery\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"\*!\s*jQuery\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"jquery.*?version\s*[=:]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "jQuery UI",
        "package": "jquery-ui",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"jquery-ui[/@-](?P<version>\d+\.\d+\.\d+)",
            r"jquery\.ui.*?(?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"jQuery\s+UI\s+[v-]?\s*(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "jQuery Migrate",
        "package": "jquery-migrate",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"jquery-migrate[/@-](?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"jQuery\s+Migrate\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Bootstrap",
        "package": "bootstrap",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"bootstrap[/@-](?P<version>\d+\.\d+\.\d+)",
            r"bootstrap\.min\.(js|css)",
            r"bootstrap\.bundle\.min\.js",
        ],
        "content_patterns": [
            r"Bootstrap\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"\*!\s*Bootstrap\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "React",
        "package": "react",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"react[/@-](?P<version>\d+\.\d+\.\d+)",
            r"react\.production\.min\.js",
            r"react\.development\.js",
        ],
        "content_patterns": [
            r"React\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"react\.version\s*=\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "React DOM",
        "package": "react-dom",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"react-dom[/@-](?P<version>\d+\.\d+\.\d+)",
            r"react-dom\.production\.min\.js",
        ],
        "content_patterns": [
            r"ReactDOM.*?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Angular",
        "package": "@angular/core",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"angular[/@-](?P<version>\d+\.\d+\.\d+)",
            r"angular\.min\.js",
        ],
        "content_patterns": [
            r"AngularJS\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"angular.*?version['\"]?\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Vue.js",
        "package": "vue",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"vue[/@-](?P<version>\d+\.\d+\.\d+)",
            r"vue\.min\.js",
            r"vue\.global\.js",
        ],
        "content_patterns": [
            r"Vue\.js\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"vue.*?version\s*=\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Lodash",
        "package": "lodash",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"lodash[/@-](?P<version>\d+\.\d+\.\d+)",
            r"lodash\.min\.js",
        ],
        "content_patterns": [
            r"lodash\s+(?P<version>\d+\.\d+\.\d+)",
            r"\*!\s*lodash\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Moment.js",
        "package": "moment",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"moment[/@-](?P<version>\d+\.\d+\.\d+)",
            r"moment\.min\.js",
        ],
        "content_patterns": [
            r"moment.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
            r"\*!\s*moment\.js\s+[v-]?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "D3.js",
        "package": "d3",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"d3[/@-](?P<version>\d+\.\d+\.\d+)",
            r"d3\.min\.js",
            r"d3\.v\d+\.min\.js",
        ],
        "content_patterns": [
            r"d3.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Chart.js",
        "package": "chart.js",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"chart\.js[/@-](?P<version>\d+\.\d+\.\d+)",
            r"chart\.min\.js",
            r"chart\.umd\.js",
        ],
        "content_patterns": [
            r"Chart\.js\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"\*!\s*Chart\.js\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Axios",
        "package": "axios",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"axios[/@-](?P<version>\d+\.\d+\.\d+)",
            r"axios\.min\.js",
        ],
        "content_patterns": [
            r"axios\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"axios.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Socket.IO",
        "package": "socket.io-client",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"socket\.io[/@-](?P<version>\d+\.\d+\.\d+)",
            r"socket\.io\.min\.js",
        ],
        "content_patterns": [
            r"Socket\.IO\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Three.js",
        "package": "three",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"three[/@-](?P<version>\d+\.\d+\.\d+)",
            r"three\.min\.js",
            r"three\.module\.js",
        ],
        "content_patterns": [
            r"three.*?REVISION\s*=\s*['\"]?(?P<version>\d+)",
        ],
    },
    {
        "name": "Popper.js",
        "package": "@popperjs/core",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"popper[/@-](?P<version>\d+\.\d+\.\d+)",
            r"popper\.min\.js",
        ],
        "content_patterns": [
            r"Popper.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Font Awesome",
        "package": "@fortawesome/fontawesome-free",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"font-?awesome[/@-](?P<version>\d+\.\d+\.\d+)",
            r"fontawesome.*?(?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"Font\s*Awesome\s+(Free\s+)?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Animate.css",
        "package": "animate.css",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"animate\.css[/@-](?P<version>\d+\.\d+\.\d+)",
            r"animate\.min\.css",
        ],
        "content_patterns": [
            r"Animate\.css\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Underscore.js",
        "package": "underscore",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"underscore[/@-](?P<version>\d+\.\d+\.\d+)",
            r"underscore\.min\.js",
        ],
        "content_patterns": [
            r"Underscore\.js\s+(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Backbone.js",
        "package": "backbone",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"backbone[/@-](?P<version>\d+\.\d+\.\d+)",
            r"backbone\.min\.js",
        ],
        "content_patterns": [
            r"Backbone\.js\s+(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Ember.js",
        "package": "ember-source",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"ember[/@-](?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"Ember\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Handlebars",
        "package": "handlebars",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"handlebars[/@-](?P<version>\d+\.\d+\.\d+)",
            r"handlebars\.min\.js",
        ],
        "content_patterns": [
            r"Handlebars\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"handlebars.*?VERSION\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Modernizr",
        "package": "modernizr",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"modernizr[/@-](?P<version>\d+\.\d+\.\d+)",
            r"modernizr\.min\.js",
        ],
        "content_patterns": [
            r"Modernizr\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"modernizr.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Highlight.js",
        "package": "highlight.js",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"highlight\.js[/@-](?P<version>\d+\.\d+\.\d+)",
            r"highlight\.min\.js",
        ],
        "content_patterns": [
            r"highlight\.js.*?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Leaflet",
        "package": "leaflet",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"leaflet[/@-](?P<version>\d+\.\d+\.\d+)",
            r"leaflet\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Leaflet\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Swiper",
        "package": "swiper",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"swiper[/@-](?P<version>\d+\.\d+\.\d+)",
            r"swiper-bundle\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Swiper\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "GSAP",
        "package": "gsap",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"gsap[/@-](?P<version>\d+\.\d+\.\d+)",
            r"gsap\.min\.js",
        ],
        "content_patterns": [
            r"GSAP\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"gsap.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Select2",
        "package": "select2",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"select2[/@-](?P<version>\d+\.\d+\.\d+)",
            r"select2\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Select2\s+(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "DataTables",
        "package": "datatables.net",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"datatables[/@-](?P<version>\d+\.\d+\.\d+)",
            r"dataTables.*?(?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"DataTables\s+(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Toastr",
        "package": "toastr",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"toastr[/@-](?P<version>\d+\.\d+\.\d+)",
            r"toastr\.min\.(js|css)",
        ],
        "content_patterns": [
            r"toastr.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "SweetAlert2",
        "package": "sweetalert2",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"sweetalert2[/@-](?P<version>\d+\.\d+\.\d+)",
            r"sweetalert2\.min\.(js|css)",
        ],
        "content_patterns": [
            r"SweetAlert2\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Alpine.js",
        "package": "alpinejs",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"alpinejs[/@-](?P<version>\d+\.\d+\.\d+)",
            r"alpine.*?(?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"Alpine.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "htmx",
        "package": "htmx.org",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"htmx[/@-](?P<version>\d+\.\d+\.\d+)",
            r"htmx\.min\.js",
        ],
        "content_patterns": [
            r"htmx.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Tailwind CSS",
        "package": "tailwindcss",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"tailwindcss[/@-](?P<version>\d+\.\d+\.\d+)",
            r"tailwind.*?(?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"tailwindcss\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Normalize.css",
        "package": "normalize.css",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"normalize\.css[/@-](?P<version>\d+\.\d+\.\d+)",
            r"normalize\.min\.css",
        ],
        "content_patterns": [
            r"normalize\.css\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Typed.js",
        "package": "typed.js",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"typed\.js[/@-](?P<version>\d+\.\d+\.\d+)",
            r"typed\.min\.js",
        ],
        "content_patterns": [
            r"Typed\.js\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Plyr",
        "package": "plyr",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"plyr[/@-](?P<version>\d+\.\d+\.\d+)",
            r"plyr\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Plyr\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Day.js",
        "package": "dayjs",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"dayjs[/@-](?P<version>\d+\.\d+\.\d+)",
            r"dayjs\.min\.js",
        ],
        "content_patterns": [
            r"dayjs.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Luxon",
        "package": "luxon",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"luxon[/@-](?P<version>\d+\.\d+\.\d+)",
            r"luxon\.min\.js",
        ],
        "content_patterns": [
            r"luxon.*?VERSION\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "AOS (Animate On Scroll)",
        "package": "aos",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"aos[/@-](?P<version>\d+\.\d+\.\d+)",
            r"aos\.min\.(js|css)",
        ],
        "content_patterns": [
            r"AOS.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Svelte",
        "package": "svelte",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"svelte[/@-](?P<version>\d+\.\d+\.\d+)",
            r"svelte\.min\.js",
        ],
        "content_patterns": [
            r"Svelte\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Preact",
        "package": "preact",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"preact[/@-](?P<version>\d+\.\d+\.\d+)",
            r"preact\.min\.js",
        ],
        "content_patterns": [
            r"preact.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Bulma",
        "package": "bulma",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"bulma[/@-](?P<version>\d+\.\d+\.\d+)",
            r"bulma\.min\.css",
        ],
        "content_patterns": [
            r"Bulma\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Foundation",
        "package": "foundation-sites",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"foundation[/@-](?P<version>\d+\.\d+\.\d+)",
            r"foundation\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Foundation\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Materialize CSS",
        "package": "materialize-css",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"materialize[/@-](?P<version>\d+\.\d+\.\d+)",
            r"materialize\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Materialize\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Semantic UI",
        "package": "semantic-ui",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"semantic[/@-](?P<version>\d+\.\d+\.\d+)",
            r"semantic\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Semantic\s+UI\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Highcharts",
        "package": "highcharts",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"highcharts[/@-](?P<version>\d+\.\d+\.\d+)",
            r"highcharts\.js",
        ],
        "content_patterns": [
            r"Highcharts\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"Highcharts.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "ECharts",
        "package": "echarts",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"echarts[/@-](?P<version>\d+\.\d+\.\d+)",
            r"echarts\.min\.js",
        ],
        "content_patterns": [
            r"ECharts\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"echarts.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "ApexCharts",
        "package": "apexcharts",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"apexcharts[/@-](?P<version>\d+\.\d+\.\d+)",
            r"apexcharts\.min\.(js|css)",
        ],
        "content_patterns": [
            r"ApexCharts\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "CKEditor",
        "package": "ckeditor4",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"ckeditor[/@-](?P<version>\d+\.\d+\.\d+)",
            r"ckeditor\.js",
        ],
        "content_patterns": [
            r"CKEditor\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"CKEDITOR.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "TinyMCE",
        "package": "tinymce",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"tinymce[/@-](?P<version>\d+\.\d+\.\d+)",
            r"tinymce\.min\.js",
        ],
        "content_patterns": [
            r"TinyMCE\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"tinymce.*?majorVersion\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Quill",
        "package": "quill",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"quill[/@-](?P<version>\d+\.\d+\.\d+)",
            r"quill\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Quill\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Dropzone.js",
        "package": "dropzone",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"dropzone[/@-](?P<version>\d+\.\d+\.\d+)",
            r"dropzone\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Dropzone\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"Dropzone.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Fancybox",
        "package": "@fancyapps/fancybox",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"fancybox[/@-](?P<version>\d+\.\d+\.\d+)",
            r"jquery\.fancybox\.min\.(js|css)",
        ],
        "content_patterns": [
            r"fancyBox\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Slick Carousel",
        "package": "slick-carousel",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"slick-carousel[/@-](?P<version>\d+\.\d+\.\d+)",
            r"slick\.min\.(js|css)",
        ],
        "content_patterns": [
            r"slick\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Owl Carousel",
        "package": "owl.carousel",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"owl\.carousel[/@-](?P<version>\d+\.\d+\.\d+)",
            r"owl\.carousel\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Owl\s+Carousel\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Isotope",
        "package": "isotope-layout",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"isotope[/@-](?P<version>\d+\.\d+\.\d+)",
            r"isotope\.pkgd\.min\.js",
        ],
        "content_patterns": [
            r"Isotope\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Masonry",
        "package": "masonry-layout",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"masonry[/@-](?P<version>\d+\.\d+\.\d+)",
            r"masonry\.pkgd\.min\.js",
        ],
        "content_patterns": [
            r"Masonry\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Video.js",
        "package": "video.js",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"video\.js[/@-](?P<version>\d+\.\d+\.\d+)",
            r"video\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Video\.js\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "MathJax",
        "package": "mathjax",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"mathjax[/@-](?P<version>\d+\.\d+\.\d+)",
            r"MathJax\.js",
        ],
        "content_patterns": [
            r"MathJax\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"MathJax.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "KaTeX",
        "package": "katex",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"katex[/@-](?P<version>\d+\.\d+\.\d+)",
            r"katex\.min\.(js|css)",
        ],
        "content_patterns": [
            r"KaTeX\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"katex.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Prism.js",
        "package": "prismjs",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"prism[/@-](?P<version>\d+\.\d+\.\d+)",
            r"prism\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Prism\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Tippy.js",
        "package": "tippy.js",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"tippy\.js[/@-](?P<version>\d+\.\d+\.\d+)",
            r"tippy\.umd\.min\.js",
        ],
        "content_patterns": [
            r"Tippy\.js\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Next.js",
        "package": "next",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"next[/@-](?P<version>\d+\.\d+\.\d+)",
            r"_next/static/chunks/(?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"Next\.js\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"next.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Nuxt.js",
        "package": "nuxt",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"nuxt[/@-](?P<version>\d+\.\d+\.\d+)",
            r"_nuxt/(?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"Nuxt\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Gatsby",
        "package": "gatsby",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"gatsby[/@-](?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"Gatsby\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Solid.js",
        "package": "solid-js",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"solid-js[/@-](?P<version>\d+\.\d+\.\d+)",
            r"solid\.min\.js",
        ],
        "content_patterns": [
            r"Solid\.js\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Lit",
        "package": "lit",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"lit[/@-](?P<version>\d+\.\d+\.\d+)",
            r"lit-all\.min\.js",
        ],
        "content_patterns": [
            r"LitElement\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Hotwire Turbo",
        "package": "@hotwired/turbo",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"turbo[/@-](?P<version>\d+\.\d+\.\d+)",
            r"turbo\.es2017\.umd\.js",
        ],
        "content_patterns": [
            r"Turbo\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Material-UI / MUI",
        "package": "@mui/material",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"material-ui[/@-](?P<version>\d+\.\d+\.\d+)",
            r"mui[/@-](?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"Material-UI\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"MUI\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Ant Design",
        "package": "antd",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"antd[/@-](?P<version>\d+\.\d+\.\d+)",
            r"antd\.min\.(js|css)",
        ],
        "content_patterns": [
            r"antd\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Vuetify",
        "package": "vuetify",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"vuetify[/@-](?P<version>\d+\.\d+\.\d+)",
            r"vuetify\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Vuetify\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "DOMPurify",
        "package": "dompurify",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"dompurify[/@-](?P<version>\d+\.\d+\.\d+)",
            r"purify\.min\.js",
        ],
        "content_patterns": [
            r"DOMPurify\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"DOMPurify.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "CryptoJS",
        "package": "crypto-js",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"crypto-js[/@-](?P<version>\d+\.\d+\.\d+)",
            r"crypto-js\.min\.js",
        ],
        "content_patterns": [
            r"CryptoJS\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "PDF.js",
        "package": "pdfjs-dist",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"pdfjs-dist[/@-](?P<version>\d+\.\d+\.\d+)",
            r"pdf\.min\.js",
        ],
        "content_patterns": [
            r"PDF\.js\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"pdfjs.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "RxJS",
        "package": "rxjs",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"rxjs[/@-](?P<version>\d+\.\d+\.\d+)",
            r"rxjs\.umd\.min\.js",
        ],
        "content_patterns": [
            r"RxJS\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Pixi.js",
        "package": "pixi.js",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"pixi\.js[/@-](?P<version>\d+\.\d+\.\d+)",
            r"pixi\.min\.js",
        ],
        "content_patterns": [
            r"PixiJS\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"PIXI.*?VERSION\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Phaser",
        "package": "phaser",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"phaser[/@-](?P<version>\d+\.\d+\.\d+)",
            r"phaser\.min\.js",
        ],
        "content_patterns": [
            r"Phaser\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"Phaser.*?VERSION\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Lottie Web",
        "package": "lottie-web",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"lottie-web[/@-](?P<version>\d+\.\d+\.\d+)",
            r"lottie\.min\.js",
        ],
        "content_patterns": [
            r"lottie-web\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Clipboard.js",
        "package": "clipboard",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"clipboard[/@-](?P<version>\d+\.\d+\.\d+)",
            r"clipboard\.min\.js",
        ],
        "content_patterns": [
            r"clipboard\.js\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Hammer.js",
        "package": "hammerjs",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"hammerjs[/@-](?P<version>\d+\.\d+\.\d+)",
            r"hammer\.min\.js",
        ],
        "content_patterns": [
            r"Hammer\.JS\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "NProgress",
        "package": "nprogress",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"nprogress[/@-](?P<version>\d+\.\d+\.\d+)",
            r"nprogress\.min\.(js|css)",
        ],
        "content_patterns": [
            r"NProgress\s+v?(?P<version>\d+\.\d+\.\d+)",
            r"NProgress.*?version\s*[:=]\s*['\"](?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "ScrollMagic",
        "package": "scrollmagic",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"scrollmagic[/@-](?P<version>\d+\.\d+\.\d+)",
            r"ScrollMagic\.min\.js",
        ],
        "content_patterns": [
            r"ScrollMagic\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Ionicons",
        "package": "ionicons",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"ionicons[/@-](?P<version>\d+\.\d+\.\d+)",
            r"ionicons\.esm\.js",
        ],
        "content_patterns": [
            r"Ionicons\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Bootstrap Table",
        "package": "bootstrap-table",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"bootstrap-table[/@-](?P<version>\d+\.\d+\.\d+)",
            r"bootstrap-table\.min\.(js|css)",
        ],
        "content_patterns": [
            r"Bootstrap\s+Table\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "React Query",
        "package": "@tanstack/react-query",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"react-query[/@-](?P<version>\d+\.\d+\.\d+)",
            r"tanstack-react-query[/@-](?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"ReactQuery\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
    {
        "name": "Apollo Client",
        "package": "@apollo/client",
        "ecosystem": "npm",
        "cdn_patterns": [
            r"apollo-client[/@-](?P<version>\d+\.\d+\.\d+)",
        ],
        "content_patterns": [
            r"ApolloClient\s+v?(?P<version>\d+\.\d+\.\d+)",
        ],
    },
]


# ---------------------------------------------------------------------------
# Core Functions
# ---------------------------------------------------------------------------

def fingerprint_resource(url, content=None):
    """
    Attempt to identify a library name and version from a resource URL
    and optionally its fetched content.
    Returns (name, version, package, ecosystem) or (None, None, None, None).
    """
    url_lower = url.lower()

    for sig in LIBRARY_SIGNATURES:
        # Strategy 1: Match against CDN URL patterns
        for pattern in sig["cdn_patterns"]:
            m = re.search(pattern, url_lower, re.IGNORECASE)
            if m:
                version = m.groupdict().get("version")
                if version:
                    return sig["name"], version, sig["package"], sig["ecosystem"]

        # Strategy 1b: URL basename match (no version yet, will try content)
        basename_patterns = [p for p in sig["cdn_patterns"] if "version" not in p]
        url_matches_lib = any(re.search(p, url_lower, re.IGNORECASE) for p in basename_patterns)

        # Strategy 2: Content-based regex (if content available)
        if content and (url_matches_lib or True):
            for pattern in sig.get("content_patterns", []):
                m = re.search(pattern, content[:5000], re.IGNORECASE)
                if m:
                    version = m.groupdict().get("version")
                    if version:
                        return sig["name"], version, sig["package"], sig["ecosystem"]

        # If URL matched a basename pattern but no version found, still record it
        if url_matches_lib:
            return sig["name"], "unknown", sig["package"], sig["ecosystem"]

    return None, None, None, None


def query_osv_batch(components):
    """
    Query the OSV.dev API in batch mode for CVE information.
    components: list of dicts with 'package' and 'version' keys.
    Returns a dict mapping (package, version) -> list of vulnerability dicts.
    """
    queries = []
    valid_components = []

    for comp in components:
        if comp.get("version") and comp["version"] != "unknown":
            queries.append({
                "version": comp["version"],
                "package": {
                    "name": comp["package"],
                    "ecosystem": comp.get("ecosystem", "npm")
                }
            })
            valid_components.append(comp)

    if not queries:
        return {}

    results = {}
    try:
        response = requests.post(
            "https://api.osv.dev/v1/querybatch",
            json={"queries": queries},
            timeout=15,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            data = response.json()
            batch_results = data.get("results", [])

            for i, batch_entry in enumerate(batch_results):
                if i >= len(valid_components):
                    break

                comp = valid_components[i]
                vulns = batch_entry.get("vulns", [])
                key = (comp["package"], comp["version"])

                parsed_vulns = []
                for vuln in vulns:
                    # Extract CVE alias if available
                    aliases = vuln.get("aliases", [])
                    cve_id = None
                    for alias in aliases:
                        if alias.startswith("CVE-"):
                            cve_id = alias
                            break

                    vuln_id = cve_id or vuln.get("id", "Unknown")

                    # Extract severity
                    severity = "Unknown"
                    severity_list = vuln.get("severity", [])
                    if severity_list:
                        score_str = severity_list[0].get("score", "")
                        # Try to parse CVSS score
                        cvss_match = re.search(r"CVSS:[\d.]+/AV:\w", score_str)
                        if cvss_match:
                            severity = classify_cvss_vector(score_str)
                        else:
                            severity = "Medium"  # Default if unparseable
                    
                    # Use database_specific severity if available
                    db_specific = vuln.get("database_specific", {})
                    if db_specific.get("severity"):
                        severity = db_specific["severity"].capitalize()

                    parsed_vulns.append({
                        "id": vuln_id,
                        "osv_id": vuln.get("id", ""),
                        "severity": severity,
                        "summary": vuln.get("summary", vuln.get("details", "No description available."))[:300],
                        "published": vuln.get("published", ""),
                        "references": [ref.get("url", "") for ref in vuln.get("references", [])[:3]],
                    })

                results[key] = parsed_vulns
        else:
            logger.warning(f"OSV API returned status {response.status_code}")
    except Exception as e:
        logger.error(f"OSV API query failed: {e}")

    return results


def classify_cvss_vector(vector_str):
    """Classify a CVSS vector string into a severity label."""
    # Try to extract numeric score from CVSS vector
    score_match = re.search(r"(\d+\.?\d*)", vector_str)
    if score_match:
        score = float(score_match.group(1))
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
    return "Medium"


def run_supply_chain_scan(url, html_content=None):
    """
    Main entry point: scans a target URL for third-party libraries,
    fingerprints them, and cross-references CVEs via OSV.dev.

    Returns:
        dict with keys: status, components, findings, summary
    """
    findings = []
    components = []
    seen_libs = set()  # Deduplicate by (name, version)

    # 1. Fetch HTML if not provided
    if not html_content:
        try:
            headers = {"User-Agent": "WebGuardScanner/1.0"}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code != 200:
                return {
                    "status": "Error",
                    "error": f"Failed to retrieve page HTML (HTTP {response.status_code})",
                    "components": [],
                    "findings": []
                }
            html_content = response.text
        except Exception as e:
            return {
                "status": "Error",
                "error": f"Connection error: {str(e)}",
                "components": [],
                "findings": []
            }

    # 2. Parse HTML
    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception as e:
        return {
            "status": "Error",
            "error": f"Failed to parse HTML: {str(e)}",
            "components": [],
            "findings": []
        }

    # 3. Extract and fingerprint all <script src="..."> tags
    script_tags = soup.find_all("script", src=True)
    for tag in script_tags:
        src = tag.get("src", "")
        abs_src = urljoin(url, src)

        # Try URL-based fingerprint first
        name, version, package, ecosystem = fingerprint_resource(abs_src)

        # If URL matched but no version, try to fetch content
        if name and version == "unknown":
            try:
                script_res = requests.get(abs_src, timeout=5, headers={"User-Agent": "WebGuardScanner/1.0"})
                if script_res.status_code == 200:
                    name2, version2, package2, ecosystem2 = fingerprint_resource(abs_src, script_res.text)
                    if version2 and version2 != "unknown":
                        version = version2
            except Exception:
                pass

        if name and (name, version) not in seen_libs:
            seen_libs.add((name, version))
            components.append({
                "name": name,
                "version": version,
                "source_url": abs_src,
                "package": package,
                "ecosystem": ecosystem,
                "type": "script",
                "cves": []
            })

    # 4. Extract and fingerprint all <link rel="stylesheet" href="..."> tags
    link_tags = soup.find_all("link", rel="stylesheet")
    for tag in link_tags:
        href = tag.get("href", "")
        if not href:
            continue
        abs_href = urljoin(url, href)

        name, version, package, ecosystem = fingerprint_resource(abs_href)

        if name and (name, version) not in seen_libs:
            seen_libs.add((name, version))
            components.append({
                "name": name,
                "version": version,
                "source_url": abs_href,
                "package": package,
                "ecosystem": ecosystem,
                "type": "stylesheet",
                "cves": []
            })

    # 5. Query OSV.dev for CVEs in batch
    cve_results = query_osv_batch(components)

    total_cves = 0
    vulnerable_count = 0

    for comp in components:
        key = (comp["package"], comp["version"])
        vulns = cve_results.get(key, [])
        comp["cves"] = vulns

        if vulns:
            vulnerable_count += 1
            total_cves += len(vulns)

            # Generate findings for each CVE
            for vuln in vulns:
                sev = vuln.get("severity", "Medium")
                findings.append({
                    "check": f"Vulnerable Component: {comp['name']} {comp['version']} ({vuln['id']})",
                    "status": "FAIL",
                    "severity": sev if sev in ["Critical", "High", "Medium", "Low"] else "Medium",
                    "description": (
                        f"The third-party library **{comp['name']} v{comp['version']}** loaded from "
                        f"`{comp['source_url']}` has a known vulnerability: **{vuln['id']}**. "
                        f"{vuln.get('summary', '')}"
                    ),
                    "recommendation": (
                        f"Upgrade {comp['name']} to the latest patched version. "
                        f"Check {vuln.get('references', ['https://osv.dev'])[0] if vuln.get('references') else 'https://osv.dev'} for details."
                    ),
                    "details": f"Library: {comp['name']}\nVersion: {comp['version']}\nCVE: {vuln['id']}\nOSV ID: {vuln.get('osv_id', '')}\nPublished: {vuln.get('published', 'N/A')}"
                })

    # 6. Add informational finding for each detected component (even if safe)
    for comp in components:
        status = "FAIL" if comp["cves"] else "PASS"
        findings.append({
            "check": f"Supply-Chain Component: {comp['name']} {comp['version']}",
            "status": status,
            "severity": "Info",
            "description": (
                f"Detected third-party {comp['type']} component **{comp['name']}** "
                f"version **{comp['version']}** loaded from `{comp['source_url']}`. "
                f"{'⚠️ ' + str(len(comp['cves'])) + ' known CVE(s) found.' if comp['cves'] else '✅ No known CVEs found.'}"
            ),
        })

    return {
        "status": "Success",
        "components": components,
        "findings": findings,
        "summary": {
            "total_components": len(components),
            "vulnerable_components": vulnerable_count,
            "total_cves": total_cves,
            "safe_components": len(components) - vulnerable_count,
        }
    }
