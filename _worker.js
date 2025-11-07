/**
 * 杩欐槸涓€涓?Cloudflare Worker 妯℃嫙 (Mock) API 鏈嶅姟鍣ㄣ€? * 瀹冧細杩斿洖鎵€鏈夊墠绔〉闈㈡墍闇€鐨勫亣鏁版嵁锛岀敤浜庡湪娌℃湁鏁版嵁搴撶殑鎯呭喌涓嬭繘琛屾祴璇曘€? */
import { Router, error, json } from 'itty-router';
// --- 妯℃嫙鏁版嵁搴?(Mock DB) ---
const mockCategories = [
    { id: 1, name: '瀛︿範璧勬枡', slug: 'study' },
    { id: 2, name: '杞欢璁稿彲', slug: 'software' },
];

const mockProducts = [
    { 
        id: 1, 
        category_id: 2, 
        name: 'Super OS 涓撲笟鐗?, 
        description: '鍔熻兘寮哄ぇ鐨勬搷浣滅郴缁燂紝閫傜敤浜庝笓涓氫汉澹€?, 
        base_price: 100.00,
        image_url: 'https://placehold.co/600x400/3b82f6/ffffff?text=Super+OS',
        variants: [
            { id: 101, name: '1骞磋鍙?, price_adjustment: 0 },
            { id: 102, name: '姘镐箙璁稿彲', price_adjustment: 150.00 },
        ]
    },
    // ... 鍏朵粬鍟嗗搧 ...
];

const mockArticles = [
    {
        id: 1,
        title: '娆㈣繋鏉ュ埌鎴戜滑鐨勭綉绔?,
        slug: 'welcome',
        summary: '浜嗚В濡備綍浣跨敤鏈珯璐拱鎮ㄩ渶瑕佺殑鍟嗗搧銆?,
        created_at: '2025-01-01T10:00:00Z',
        content: '<h2>娆㈣繋锛?/h2><p>...</p>'
    },
];

const mockOrders = new Map();

// --- 妯℃嫙鍚庡彴璁剧疆 (閲嶈锛? ---
// 绉婚櫎浜嗙‖缂栫爜鐨?MOCK_ADMIN_USERNAME, MOCK_ADMIN_PASSWORD, 鍜?MOCK_ADMIN_TOKEN
// 杩欎簺鐜板湪灏嗕粠 Cloudflare Worker 鐨勫姞瀵?Secrets 涓鍙?(env.ADMIN_USER, env.ADMIN_PASS, env.ADMIN_TOKEN)
// ---------------------------------


// 鍒涘缓涓€涓柊鐨勮矾鐢?const router = Router();

// --- 杈呭姪鍑芥暟锛氭鏌?Admin Token ---
const withAuth = (request, env) => { // <-- 澧炲姞浜?'env' 鍙傛暟
    const authHeader = request.headers.get('Authorization');
    // 浣跨敤 env.ADMIN_TOKEN 鏇夸唬 MOCK_ADMIN_TOKEN
    if (authHeader !== `Bearer ${env.ADMIN_TOKEN}`) { 
        return error(401, 'Unauthorized');
    }
    // 濡傛灉 token 姝ｇ‘锛屼粈涔堜篃涓嶈繑鍥烇紝缁х画鎵ц
};

// --- 鍏叡 API 璺敱 (鍜屼互鍓嶄竴鏍? ---

router.get('/api/categories', () => {
    return json(mockCategories);
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
    // ... (姝ら儴鍒嗕笌 V1 鐩稿悓锛屼繚鎸佷笉鍙? ...
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
        qr_code_url: `https://placehold.co/200x200/ffffff/000000?text=${encodeURIComponent('妯℃嫙鏀粯\n锟? + totalAmount.toFixed(2))}`,
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
    // ... (姝ら儴鍒嗕笌 V1 鐩稿悓锛屼繚鎸佷笉鍙? ...
    const order = mockOrders.get(params.id);
    if (!order) return error(404, 'Order not found');
    return json({
        order_id: order.order_id,
        status: order.status,
        delivered_card: order.delivered_card,
    });
});


// --- 鍚庡彴绠＄悊 API 璺敱 (鍏ㄦ柊锛? ---

// 1. 鐧诲綍
router.post('/api/admin/login', async (request, env) => { // <-- 澧炲姞浜?'env' 鍙傛暟
    const { username, password } = await request.json();
    
    // !! 瀹夊叏鐨勬紨绀猴細浠庡姞瀵嗙殑鐜鍙橀噺涓鍙栧笎鍙峰瘑鐮?!!
    if (username === env.ADMIN_USER && password === env.ADMIN_PASS) { // <-- 浣跨敤 env 鍙橀噺
        return json({ token: env.ADMIN_TOKEN }); // <-- 浣跨敤 env 鍙橀噺
    } else {
        return error(401, '甯愬彿鎴栧瘑鐮侀敊璇?);
    }
});

// 2. 鑾峰彇鎵€鏈夊晢鍝?(鍙椾繚鎶?
router.get('/api/admin/products', withAuth, () => {
    // 鐪熷疄搴旂敤锛?return await env.DB.query...
    return json(mockProducts);
});

// 3. 娣诲姞鏂板晢鍝?(鍙椾繚鎶?
router.post('/api/admin/products', withAuth, async (request) => {
    const newProduct = await request.json();
    newProduct.id = Math.floor(Math.random() * 1000) + 10; // 妯℃嫙 ID
    mockProducts.push(newProduct);
    console.log('Added product (mock):', JSON.stringify(newProduct));
    return json(newProduct, { status: 201 });
});

// 4. 鍒犻櫎鍟嗗搧 (鍙椾繚鎶?
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

// 5. 鑾峰彇鎵€鏈夋枃绔?(鍙椾繚鎶?
router.get('/api/admin/articles', withAuth, () => {
    return json(mockArticles);
});

// 6. 娣诲姞鏂版枃绔?(鍙椾繚鎶?
router.post('/api/admin/articles', withAuth, async (request) => {
    const newArticle = await request.json();
    newArticle.id = Math.floor(Math.random() * 1000) + 10;
    mockArticles.push(newArticle);
    console.log('Added article (mock):', JSON.stringify(newArticle));
    return json(newArticle, { status: 201 });
});


// --- 404 澶勭悊 ---
router.all('*', () => error(404, 'API endpoint not found'));

// --- Worker 鍏ュ彛 ---
export default {
    fetch: (request, env, ctx) => // <-- 纭繚 env 琚紶閫?        router.handle(request, env, ctx),
};
