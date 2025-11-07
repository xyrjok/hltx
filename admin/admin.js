// admin/admin.js

/**
 * 页面初始化：设置退出登录按钮
 */
document.addEventListener('DOMContentLoaded', () => {
    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            sessionStorage.removeItem('admin-token');
            window.location.href = '/admin/index.html';
        });
    }
});

// 2. 统一的 Fetch 封装
const token = sessionStorage.getItem('admin-token');

/**
 * 带有 Authorization Header 和基础错误处理的 Fetch 封装。
 * 所有页面逻辑都应使用此函数代替原生的 fetch。
 * @param {string} url - API 路径
 * @param {object} options - Fetch 选项
 * @returns {Promise<any>} - 返回解析后的 JSON 数据或 Response 对象
 */
async function adminFetch(url, options = {}) {
    if (!token) {
        throw new Error("未找到管理员令牌，请重新登录。");
    }

    const defaultHeaders = {
        'Authorization': `Bearer ${token}`,
        // 只有当有 body 时才设置 Content-Type
        'Content-Type': options.body ? 'application/json' : undefined
    };

    const finalOptions = {
        ...options,
        headers: {
            ...defaultHeaders,
            ...options.headers
        }
    };

    const response = await fetch(url, finalOptions);

    if (!response.ok) {
        let errorMessage = response.statusText || '请求失败';
        try {
            const errorJson = await response.json();
            errorMessage = errorJson.message || errorMessage;
        } catch (e) {
            // 忽略非 JSON 响应体的解析错误
        }
        
        // 如果是 401/403，提示并强制退出
        if (response.status === 401 || response.status === 403) {
             sessionStorage.removeItem('admin-token');
             alert(`会话过期或权限不足: ${errorMessage}，将跳转至登录页。`);
             window.location.href = '/admin/index.html';
        }
        throw new Error(`API 错误 (${response.status}): ${errorMessage}`);
    }

    // 对于 GET/HEAD 请求，解析 JSON
    if (options.method === 'GET' || !options.method) {
        // 如果响应体为空，返回空对象
        if (response.headers.get('content-length') === '0' || response.status === 204) {
             return {};
        }
        return response.json();
    }
    
    // 对于其他请求，返回响应对象或成功状态
    return response;
}
