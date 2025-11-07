/**
 * 杩欐槸涓€涓?Cloudflare Worker 妯℃嫙 (Mock) API 鏈嶅姟鍣ㄣ€? * 瀹冧細杩斿洖鎵€鏈夊墠绔〉闈㈡墍闇€鐨勫亣鏁版嵁锛岀敤浜庡湪娌℃湁鏁版嵁搴撶殑鎯呭喌涓嬭繘琛屾祴璇曘€? */
import { Router, error, json } from 'itty-router';
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
            { id: 101, name: '1年许可', price_adjustment: 0, stock_count: 50 }, // 模拟库存
            { id: 102, name: '永久许可', price_adjustment: 150.00, stock_count: 10 }, // 模拟库存
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
const mockCards = [
    { id: 1, variant_id: 101, card_key: 'KEY-101-ABCDEF', is_used: 0, created_at: '2025-10-01T00:00:00Z' },
    { id: 2, variant_id: 101, card_key: 'KEY-101-GHIJKL', is_used: 0, created_at: '2025-10-02T00:00:00Z' },
    { id: 3, variant_id: 102, card_key: 'KEY-102-MNOPQR', is_used: 0, created_at: '2025-10-03T00:00:00Z' },
];

const mockAdminOrders = [
    { order_id: 'MOCK-1700000001', product_name: 'Super OS 专业版 - 1年许可', total_amount: 100.00, status: 'paid', created_at: '2025-10-20T08:00:00Z' },
    { order_id: 'MOCK-1700000002', product_name: 'Super OS 专业版 - 永久许可', total_amount: 250.00, status: 'pending', created_at: '2025-10-21T12:30:00Z' },
];

const mockPaymentSettings = {
    alipay_partner_id: '123456789',
    wechatpay_mch_id: '987654321',
    is_enabled: 'true',
};

const mockConfigurations = {
    site_title: 'CloudCard',
    support_email: 'support@cloudcard.com',
};

// --- 模拟后台设置 (重要！) ---
// 移除了硬编码的 MOCK_ADMIN_USERNAME, MOCK_ADMIN_PASSWORD, 和 MOCK_ADMIN_TOKEN
// 这些现在将从 Cloudflare Worker 的加密 Secrets 中读取 (env.ADMIN_USER, env.ADMIN_PASS, env.ADMIN_TOKEN)
// ---------------------------------


// 创建一个新的路由
const router = Router();


// --- 公共 API 路由 (和以前一样) ---

// ... (GET /api/categories 到 GET /api/orders/:id 保持不变) ...

// GET /api/categories
router.get('/api/categories', () => {
    // 仅返回需要的字段
    const categoryList = mockCategories.map(c => ({
        id: c.id,
        name: c.name,
        slug: c.slug,
    }));
    return json(categoryList);
});

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
    const { variant_id } = await request.json();
    let foundProduct = null;
    let foundVariant = null;

    // 1. 查找商品规格并检查库存
    for (const p of mockProducts) {
        const v = p.variants.find(v => v.id === variant_id);
        if (v) {
            foundProduct = p;
            foundVariant = v;
            break;
        }
    }
    if (!foundVariant) return error(404, 'Variant not found');
    
    // 简化模拟库存检查：查找一个未使用的卡密
    const availableCardIndex = mockCards.findIndex(c => c.variant_id === variant_id && c.is_used === 0);
    if (availableCardIndex === -1 || foundVariant.stock_count <= 0) {
         return error(400, '库存不足');
    }

    // 2. 扣除库存 (模拟)
    foundVariant.stock_count -= 1; // 模拟扣除库存

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

    // 3. 模拟支付成功和卡密派发
    setTimeout(() => {
        const order = mockOrders.get(orderId);
        if (order) { 
            // 标记卡密为已使用并派发
            const cardToDeliver = mockCards[availableCardIndex];
            cardToDeliver.is_used = 1;
            
            order.status = 'paid'; 
            order.delivered_card = cardToDeliver.card_key; 
        }
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
// --- 辅助函数：检查 Admin Token ---
const withAuth = (request, env) => { // <-- 增加了 'env' 参数
    const authHeader = request.headers.get('Authorization');
    // 使用 env.ADMIN_TOKEN 替代 MOCK_ADMIN_TOKEN
    if (authHeader !== `Bearer ${env.ADMIN_TOKEN}`) { 
        return error(401, 'Unauthorized');
    }
    // 如果 token 正确，什么也不返回，继续执行
};

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

// 7. 获取所有分类 (受保护)
router.get('/api/admin/categories', withAuth, () => {
    return json(mockCategories);
});

// 8. 添加新分类 (受保护)
router.post('/api/admin/categories', withAuth, async (request) => {
    const newCategory = await request.json();
    newCategory.id = Math.floor(Math.random() * 1000) + 10;
    mockCategories.push(newCategory);
    console.log('Added category (mock):', JSON.stringify(newCategory));
    return json(newCategory, { status: 201 });
});
// 9. 获取所有订单 (受保护) - 新增
router.get('/api/admin/orders', withAuth, () => {
    // 合并 mockAdminOrders 和动态生成的 mockOrders
    const dynamicOrders = Array.from(mockOrders.values()).map(o => ({
        order_id: o.order_id,
        product_name: o.product_name,
        total_amount: o.total_amount,
        status: o.status,
        created_at: new Date().toISOString(), // 模拟创建时间
    }));
    // 真实应用中，需要从 DB 倒序取出
    return json([...mockAdminOrders, ...dynamicOrders].sort((a, b) => b.created_at.localeCompare(a.created_at)));
});

// 10. 获取卡密列表 (受保护) - 新增
router.get('/api/admin/cards', withAuth, () => {
    return json(mockCards);
});

// 11. 导入新卡密 (受保护) - 新增（简化：直接添加）
router.post('/api/admin/cards/import', withAuth, async (request) => {
    const { variant_id: variantId, keys } = await request.json();
    const variant_id = parseInt(variantId);

    // 查找并增加 ProductVariant 的 stock_count (模拟)
    let foundVariant = null;
    for (const p of mockProducts) {
        const v = p.variants.find(v => v.id === variant_id);
        if (v) {
            foundVariant = v;
            break;
        }
    }
    if (!foundVariant) return error(404, 'Variant not found');

    let addedCount = 0;
    keys.forEach(key => {
        const newCard = {
            id: Math.floor(Math.random() * 1000000) + 1000,
            variant_id: variant_id,
            card_key: key,
            is_used: 0,
            created_at: new Date().toISOString(),
        };
        mockCards.push(newCard);
        addedCount++;
    });

    foundVariant.stock_count += addedCount; // 模拟更新库存

    console.log(`Imported ${addedCount} cards for variant ${variant_id} (mock)`);
    return json({ success: true, added_count: addedCount }, { status: 201 });
});

// 12. 获取支付设置 (受保护) - 新增
router.get('/api/admin/settings/payment', withAuth, () => {
    // 真实应用：从 PaymentSettings DB 表中获取所有 key/value
    return json(mockPaymentSettings);
});

// 13. 保存支付设置 (受保护) - 新增
router.post('/api/admin/settings/payment', withAuth, async (request) => {
    const updates = await request.json();
    // 真实应用：更新 PaymentSettings DB 表中的 key/value
    Object.assign(mockPaymentSettings, updates);
    return json({ success: true, settings: mockPaymentSettings });
});

// 14. 获取通用配置 (受保护) - 新增
router.get('/api/admin/settings/config', withAuth, () => {
    // 真实应用：从 Configurations DB 表中获取所有 key/value
    return json(mockConfigurations);
});

// 15. 保存通用配置 (受保护) - 新增
router.post('/api/admin/settings/config', withAuth, async (request) => {
    const updates = await request.json();
    // 真实应用：更新 Configurations DB 表中的 key/value
    Object.assign(mockConfigurations, updates);
    return json({ success: true, configurations: mockConfigurations });
});

// --- 404 处理 ---
router.all('*', () => error(404, 'API endpoint not found'));

// --- Worker 入口 ---
export default {
    fetch: (request, env, ctx) => // <-- 确保 env 被传递
        router.handle(request, env, ctx),
};
