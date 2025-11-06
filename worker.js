/**
 * 这是一个 Cloudflare Worker 模拟 (Mock) API 服务器。
 * 它会返回所有前端页面所需的假数据，用于在没有数据库的情况下进行测试。
 */

// --- 粘贴 itty-router v4 源代码开始 ---
// 这段代码定义了您需要的 Router, json, 和 error

const T = e => e.replace(/(\/?)\*/g, "($1.*)?").replace(/\/$/, "").replace(/:(\w+)(\?)?(\.)?/g, "$3(?<$1>[^/]+)$2").replace(/\.(?=[\w(])/, "\\.");

var A = ({ base: e = "", routes: r = [] } = {}) => ({
    __proto__: new Proxy({}, {
        get: (t, o) => (...t) => (r.push([
            o.toUpperCase(),
            RegExp(`^${T(e + t[0])}/*$`),
            t.slice(1)
        ]), A({ base: e, routes: r }))
    }),
    routes: r,
    handle: async (e, ...t) => {
        let o, s, a;
        const n = new URL(e.url);
        for (var [i, c, l] of r)
            if ((i === e.method || "ALL" === i) && (s = n.pathname.match(c))) {
                e.params = s.groups, e.query = Object.fromEntries(n.searchParams.entries());
                for (var u of l)
                    if (null != (a = await u(e, ...t))) return a
            }
    }
});

const P = e => new Response(JSON.stringify(e), {
    headers: { "content-type": "application/json;charset=UTF-8" }
});

const E = (e, r = 404) => new Response(e, { status: r });

// 将库功能赋值给您代码中使用的常量
const Router = A;
const json = P;
const error = E;

// --- 粘贴 itty-router v4 源代码结束 ---

// --- 模拟数据库 (Mock DB) ---
const mockCategories = [
    { id: 1, name: '学习资料', slug: 'study' },
    { id: 2, name: '软件许可', slug: 'software' },
];

const mockProducts = [
    { 
        id: 1, 
        category_id: 2, 
        name: 'Super OS 专业版', 
        description: '功能强大的操作系统，适用于专业人士。', 
        base_price: 100.00,
        image_url: 'https://placehold.co/600x400/3b82f6/ffffff?text=Super+OS',
        variants: [
            { id: 101, name: '1年许可', price_adjustment: 0 },
            { id: 102, name: '永久许可', price_adjustment: 150.00 },
        ]
    },
    // ... 其他商品 ...
];

const mockArticles = [
    {
        id: 1,
        title: '欢迎来到我们的网站',
        slug: 'welcome',
        summary: '了解如何使用本站购买您需要的商品。',
        created_at: '2025-01-01T10:00:00Z',
        content: '<h2>欢迎！</h2><p>...</p>'
    },
];

const mockOrders = new Map();

// --- 模拟后台设置 (重要！) ---
// 移除了硬编码的 MOCK_ADMIN_USERNAME, MOCK_ADMIN_PASSWORD, 和 MOCK_ADMIN_TOKEN
// 这些现在将从 Cloudflare Worker 的加密 Secrets 中读取 (env.ADMIN_USER, env.ADMIN_PASS, env.ADMIN_TOKEN)
// ---------------------------------


// 创建一个新的路由
const router = Router();

// --- 辅助函数：检查 Admin Token ---
const withAuth = (request, env) => { // <-- 增加了 'env' 参数
    const authHeader = request.headers.get('Authorization');
    // 使用 env.ADMIN_TOKEN 替代 MOCK_ADMIN_TOKEN
    if (authHeader !== `Bearer ${env.ADMIN_TOKEN}`) { 
        return error(401, 'Unauthorized');
    }
    // 如果 token 正确，什么也不返回，继续执行
};


// --- 公共 API 路由 (和以前一样) ---

// ... (GET /api/categories 到 GET /api/orders/:id 保持不变) ...

// GET /api/products
router.get('/api/products', () => {
    const productList = mockProducts.map(p => ({
        id: p.id,
        name: p.name,
        base_price: p.base_price,
        image_url: p.image_url,
    }));
    return json(productList);
});

// GET /api/products/:id
router.get('/api/products/:id', ({ params }) => {
    const product = mockProducts.find(p => p.id === parseInt(params.id));
    if (!product) return error(404, 'Product not found');
    return json(product);
});

// GET /api/articles
router.get('/api/articles', () => {
    const articleList = mockArticles.map(a => ({
        id: a.id, title: a.title, slug: a.slug, summary: a.summary, created_at: a.created_at,
    }));
    return json(articleList);
});

// GET /api/articles/:slug
router.get('/api/articles/:slug', ({ params }) => {
    const article = mockArticles.find(a => a.slug === params.slug);
    if (!article) return error(404, 'Article not found');
    return json(article);
});

// POST /api/orders
router.post('/api/orders', async (request) => {
    // ... (此部分与 V1 相同，保持不变) ...
    const { variant_id } = await request.json();
    let foundProduct = null;
    let foundVariant = null;
    for (const p of mockProducts) {
        const v = p.variants.find(v => v.id === variant_id);
        if (v) {
            foundProduct = p;
            foundVariant = v;
            break;
        }
    }
    if (!foundVariant) return error(404, 'Variant not found');
    const totalAmount = foundProduct.base_price + foundVariant.price_adjustment;
    const orderId = `MOCK-${Date.now()}`;
    const newOrder = {
        order_id: orderId,
        product_name: `${foundProduct.name} - ${foundVariant.name}`,
        total_amount: totalAmount,
        status: 'pending',
        qr_code_url: `https://placehold.co/200x200/ffffff/000000?text=${encodeURIComponent('模拟支付\n￥' + totalAmount.toFixed(2))}`,
    };
    mockOrders.set(orderId, newOrder);
    setTimeout(() => {
        const order = mockOrders.get(orderId);
        if (order) { order.status = 'paid'; order.delivered_card = `MOCK-CARD-KEY-${Date.now()}-12345`; }
    }, 5000);
    return json(newOrder);
});

// GET /api/orders/:id
router.get('/api/orders/:id', ({ params }) => {
    // ... (此部分与 V1 相同，保持不变) ...
    const order = mockOrders.get(params.id);
    if (!order) return error(404, 'Order not found');
    return json({
        order_id: order.order_id,
        status: order.status,
        delivered_card: order.delivered_card,
    });
});


// --- 后台管理 API 路由 (全新！) ---

// 1. 登录
router.post('/api/admin/login', async (request, env) => { // <-- 增加了 'env' 参数
    const { username, password } = await request.json();
    
    // !! 安全的演示：从加密的环境变量中读取帐号密码 !!
    if (username === env.ADMIN_USER && password === env.ADMIN_PASS) { // <-- 使用 env 变量
        return json({ token: env.ADMIN_TOKEN }); // <-- 使用 env 变量
    } else {
        return error(401, '帐号或密码错误');
    }
});

// 2. 获取所有商品 (受保护)
router.get('/api/admin/products', withAuth, () => {
    // 真实应用： return await env.DB.query...
    return json(mockProducts);
});

// 3. 添加新商品 (受保护)
router.post('/api/admin/products', withAuth, async (request) => {
    const newProduct = await request.json();
    newProduct.id = Math.floor(Math.random() * 1000) + 10; // 模拟 ID
    mockProducts.push(newProduct);
    console.log('Added product (mock):', JSON.stringify(newProduct));
    return json(newProduct, { status: 201 });
});

// 4. 删除商品 (受保护)
router.delete('/api/admin/products/:id', withAuth, ({ params }) => {
    const id = parseInt(params.id);
    const index = mockProducts.findIndex(p => p.id === id);
    if (index > -1) {
        mockProducts.splice(index, 1);
        console.log(`Deleted product ${id} (mock)`);
        return json({ success: true });
    }
    return error(404, 'Product not found');
});

// 5. 获取所有文章 (受保护)
router.get('/api/admin/articles', withAuth, () => {
    return json(mockArticles);
});

// 6. 添加新文章 (受保护)
router.post('/api/admin/articles', withAuth, async (request) => {
    const newArticle = await request.json();
    newArticle.id = Math.floor(Math.random() * 1000) + 10;
    mockArticles.push(newArticle);
    console.log('Added article (mock):', JSON.stringify(newArticle));
    return json(newArticle, { status: 201 });
});


// --- 404 处理 ---
router.all('*', () => error(404, 'API endpoint not found'));

// --- Worker 入口 ---
export default {
    fetch: (request, env, ctx) => // <-- 确保 env 被传递
        router.handle(request, env, ctx),
};
