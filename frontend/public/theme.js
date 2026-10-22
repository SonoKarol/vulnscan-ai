try {
  var t = localStorage.getItem('vulnscan:theme');
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
} catch (e) {}
