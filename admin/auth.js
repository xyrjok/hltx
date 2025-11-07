// 这是一个共享脚本，用于检查所有后台页面的登录状态
// 如果未登录，它会
// 自动重定向到登录页。

if (!sessionStorage.getItem('admin-token') && !window.location.pathname.endsWith('/admin/index.html')) {
    window.location.href = '/admin/index.html';
}
