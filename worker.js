/**
 * 这是一个 Cloudflare Worker 模拟 (Mock) API 服务器。
 * 它会返回所有前端页面所需的假数据，用于在没有数据库的情况下进行测试。
 * * 如何使用：
 * 1. 登录 Cloudflare 仪表板。
 * 2. 创建一个新的 Worker 服务 (例如 "my-api-worker")。
 * 3. 点击 "Quick Edit" (快速编辑)。
 * 4. 复制此文件的全部内容，粘贴到编辑器中，覆盖掉默认代码。
 * 5. 点击 "Save and Deploy"。
 */

// 使用一个轻量级路由库
import { Router, error, json } from 'itty-router';

// --- 模拟数据库 (Mock DB) ---
// 真实项目中，这些数据将来自 D1 数据库
const mockCategories = [
    { id: 1, name: '学习资料', slug: 'study' },
    { id: 2, name: '软件许可', slug: 'software' },
    { id: 3, name: '游戏点卡', slug: 'game' },
    { id: 4, name: '会员服务', slug: 'membership' },
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
    { 
        id: 2, 
        category_id: 4, 
        name: '云视频高级会员', 
        description: '无广告，高清，多设备共享。', 
        base_price: 20.00,
        image_url: 'https://placehold.co/600x400/10b981/ffffff?text=Cloud+Video',
        variants: [
            { id: 201, name: '月卡', price_adjustment: 0 },
            { id: 202, name: '季卡', price_adjustment: 35.00 }, // 20 + 35 = 55
            { id: 203, name: '年卡', price_adjustment: 178.00 }, // 20 + 178 = 198
        ]
    },
    { 
        id: 3, 
        category_id: 3, 
        name: '幻想大陆 Online', 
        description: '1000 点游戏点卡。', 
        base_price: 100.00,
        image_url: 'https://placehold.co/600x400/f59e0b/ffffff?text=Fantasy+Game',
        variants: [
            { id: 301, name: '1000点卡', price_adjustment: 0 },
        ]
    },
];

const mockArticles = [
    {
        id: 1,
        title: '欢迎来到我们的网站',
        slug: 'welcome',
        summary: '了解如何使用本站购买您需要的商品。',
        created_at: '2025-01-01T10:00:00Z',
        content: `
            <h2>欢迎！</h2>
            <p>这是一个自动发卡网站。您可以在这里浏览商品、选择规格并自动完成购买。</p>
            <p>所有流程都是自动化的，支付成功后，您将立即收到您购买的卡密信息。</p>
            <code>祝您购物愉快！</code>
        `
    },
    {
        id: 2,
        title: '如何处理支付失败？',
        slug: 'payment-failed',
        summary: '如果您的支付未能成功，请尝试以下步骤...',
        created_at: '2025-01-02T11:00:00Z',
        content: `
            <h2>支付失败处理</h2>
            <p>如果您的支付失败，请不要担心。这可能是由以下原因造成的：</p>
            <ul>
                <li>网络连接问题</li>
                <li>账户余额不足</li>
                <li>支付网关限制</li>
            </ul>
            <p>请尝试刷新页面并重新支付。如果问题仍然存在，请联系客服（如果有的话）。</p>
        `
    },
];

// 模拟订单存储 (真实项目中在 D1)
// key: order_id, value: order_data
const mockOrders = new Map();
// ----------------------------


// 创建一个新的路由
const router = Router();

// --- 公共 API 路由 ---

// GET /api/categories
router.get('/api/categories', () => {
    return json(mockCategories);
});

// GET /api/products
// (这个模拟 API 比较简单，没有实现 ?category=slug 过滤)
router.get('/api/products', () => {
    // 仅返回基础信息，用于首页列表
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
    const id = parseInt(params.id, 10);
    const product = mockProducts.find(p => p.id === id);

    if (!product) {
        return error(404, 'Product not found');
    }
    
    // 返回包含规格的完整信息
    return json(product);
});

// GET /api/articles
router.get('/api/articles', () => {
    // 列表页不返回完整 content
    const articleList = mockArticles.map(a => ({
        id: a.id,
        title: a.title,
        slug: a.slug,
        summary: a.summary,
        created_at: a.created_at,
    }));
    return json(articleList);
});

// GET /api/articles/:slug
router.get('/api/articles/:slug', ({ params }) => {
    const slug = params.slug;
    const article = mockArticles.find(a => a.slug === slug);

    if (!article) {
        return error(404, 'Article not found');
    }
    // 详情页返回完整 content
    return json(article);
});

// POST /api/orders (创建订单)
router.post('/api/orders', async (request) => {
    const { variant_id } = await request.json();
    if (!variant_id) {
        return error(400, 'Missing variant_id');
    }

    // 查找商品和规格
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

    if (!foundVariant) {
        return error(404, 'Variant not found');
    }

    const totalAmount = foundProduct.base_price + foundVariant.price_adjustment;
    const orderId = `MOCK-${Date.now()}`;

    // 模拟创建订单
    const newOrder = {
        order_id: orderId,
        variant_id: variant_id,
        product_name: `${foundProduct.name} - ${foundVariant.name}`,
        total_amount: totalAmount,
        status: 'pending', // 初始状态为 pending
        delivered_card: null,
        qr_code_url: `https://placehold.co/200x200/ffffff/000000?text=${encodeURIComponent('模拟支付\n￥' + totalAmount.toFixed(2))}`, // 模拟二维码
        created_at: Date.now(),
    };

    mockOrders.set(orderId, newOrder);
    
    // 模拟支付成功 (在真实应用中，这是由 Webhook 触发的)
    // 为了演示，我们在 5 秒后自动把订单标记为 "paid"
    setTimeout(() => {
        const order = mockOrders.get(orderId);
        if (order && order.status === 'pending') {
            order.status = 'paid';
            order.delivered_card = `MOCK-CARD-KEY-${Date.now()}-12345`;
        }
    }, 5000); // 5 秒后自动支付

    return json(newOrder);
});

// GET /api/orders/:id (查询订单状态)
router.get('/api/orders/:id', ({ params }) => {
    const orderId = params.id;
    const order = mockOrders.get(orderId);

    if (!order) {
        return error(404, 'Order not found');
    }

    // 只返回前端需要的信息
    return json({
        order_id: order.order_id,
        status: order.status,
        delivered_card: order.delivered_card, // 只有 'paid' 状态下才有值
    });
});

// --- 404 处理 ---
router.all('*', () => error(404, 'API endpoint not found'));

// --- Worker 入口 ---
export default {
    fetch: router.handle,
};
